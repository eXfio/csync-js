/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave Sync client supporting Storage v5 and Storage API v1.1
 *
 *  LICENSE:
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

//npm includes
var sprintf = require('sprintf').sprintf;
var forge   = require('node-forge');
var P       = require('p-promise');

//other third party includes
//var JSON = require('./lib/json2');

//app includes
var weave = {};
weave.error = require('./weave-error');
weave.util = require('./weave-util');
weave.storage = require('./weave-storage');

crypto = {};

crypto.WeaveKeyPair = function() {
  this.cryptKey = null;
  this.hmacKey  = null;
}

crypto.CryptoClientFactory = (function() {
  return {
    getInstance: function(storageClient, cryptoParams) {
      //Currently only CryptoClientV5 is supported so instansiate it directly
      //var cryptoClient = new crypto["CryptoClient" + cryptoParams.apiVersion.toUpperCase()]();
      var cryptoClient = new crypto.CryptoClientV5();
      cryptoClient.init(storageClient, cryptoParams);
      return cryptoClient;
    }
  };
})();

crypto.CryptoClient = function() {
  this.storageClient = null;
  this.privateKey    = null;
  this.bulkKeys      = null;
}

crypto.CryptoClient.prototype = {
    
  KEY_CRYPTO_PATH:       "crypto/keys",
  KEY_CRYPTO_COLLECTION: "crypto",
  KEY_CRYPTO_ID:         "keys",
  KEY_META_PATH:         "meta/global",
  KEY_META_COLLECTION:   "meta",
  KEY_META_ID:           "global",
  
  init: function(storageClient, cryptoParams) {
	this.storageClient   = storageClient;
	this.privateKey      = cryptoParams.keyPair;
	this.bulkKeys        = null;		
  },
  
  isEncrypted: function(wbo) {
	//Determine if WBO is encrypted or not
	var jsonPayload  = wbo.getPayloadAsJSONObject();
	return ( 'ciphertext' in jsonPayload &&  'IV' in jsonPayload && 'hmac' in jsonPayload );
  },
  
  decryptWeaveBasicObject: function(encWbo, collection) {
    weave.util.Log.debug("CryptoClient.decryptWeaveBasicObject()");

	if ( !this.isEncrypted(encWbo) ) {
	  throw new weave.error.WeaveError("Weave Basic Object already decrypted");
	}

    return this.decrypt(encWbo.payload, collection)
      .then(function(payload) {
        var decWbo = new weave.storage.WeaveBasicObject();
	    decWbo.id         = encWbo.id
	    decWbo.modified   = encWbo.modified;
	    decWbo.sortindex  = encWbo.sortindex;
	    decWbo.payload    = payload;
	    decWbo.ttl        = encWbo.ttl;
        return P(decWbo);
      });
  },

  encryptWeaveBasicObject: function(decWbo, collection) {
    weave.util.Log.debug("CryptoClient.encryptWeaveBasicObject()");

	if ( this.isEncrypted(decWbo) ) {
	  throw new weave.error.WeaveError("Weave Basic Object already encrypted");
	}

    return this.encrypt(decWbo.payload, collection)
      .then(function(payload) {
        var encWbo = new weave.storage.WeaveBasicObject();
	    encWbo.id         = decWbo.id
	    encWbo.modified   = decWbo.modified;
	    encWbo.sortindex  = decWbo.sortindex;
	    encWbo.payload    = payload;
	    encWbo.ttl        = decWbo.ttl;
        return P(encWbo);
      });
  },

  decrypt: function(payload, collection) {
    weave.util.Log.debug("CryptoClient.decrypt()");
    
    var keyPair = new crypto.WeaveKeyPair();
    
    if ( collection === null ) {
      weave.util.Log.info("Decrypting data record using sync key");
      
      try {
        keyPair = this.privateKey;
      } catch(e){
        throw new weave.error.WeaveError(e.message);
      }

      var plaintext = crypto.PayloadCipher.decrypt(payload, keyPair);
      return P(plaintext);
    } else {
      weave.util.Log.info(sprintf("Decrypting data record using bulk key %s", collection));
      
      return this.getBulkKeyPair(collection)
        .then(function(keyPair) {
          var plaintext = crypto.PayloadCipher.decrypt(payload, keyPair);
          return P(plaintext);
        });
    }
  },

  encrypt: function(payload, collection) {
    weave.util.Log.debug("CryptoClient.encrypt()");
    
    var keyPair = new crypto.WeaveKeyPair();
    
    if ( collection === null ) {
      weave.util.Log.info("Encrypting data record using sync key");
      
      try {
        keyPair = this.privateKey;
      } catch(e){
        throw new weave.error.WeaveError(e.message);
      }

      var ciphertext = crypto.PayloadCipher.encrypt(payload, keyPair);
      return P(ciphertext);
    } else {
      weave.util.Log.info(sprintf("Encrypting data record using bulk key %s", collection));
      
      return this.getBulkKeyPair(collection)
        .then(function(keyPair) {
          var ciphertext = crypto.PayloadCipher.encrypt(payload, keyPair);
          return P(ciphertext);
        });
    }
  },

  /**
   * Given a bulk key label, pull the key down from the network,
   * and decrypt it using my private key.  Then store the key
   * into self storage for later decrypt operations.
   */
  getBulkKeyPair: function(collection) {
	weave.util.Log.debug("CryptoClientClient.getBulkKeyPair()");

    var self = this;
    
	if ( this.bulkKeys === null ) {
	  weave.util.Log.info("Fetching bulk keys from server");
      
      return this.storageClient.get(this.KEY_CRYPTO_COLLECTION, this.KEY_CRYPTO_ID, true)
        .then(function(res) {
          // Recursively call decrypt to extract key data
          return self.decrypt(res.payload, null)
        })
        .then(function(payload) {
          
          var keyData = JSON.parse(payload);

          self.bulkKeys   = {};
      
          //Get default key pair
          var defaultKey = keyData['default'];
      
          var keyPair = new crypto.WeaveKeyPair();
          keyPair.cryptKey = forge.util.createBuffer(weave.util.Base64.decode(defaultKey[0]));
          keyPair.hmacKey  = forge.util.createBuffer(weave.util.Base64.decode(defaultKey[1]));
          self.bulkKeys['default'] = keyPair;
          
          //Get collection key pairs
          var colKey = keyData['collections']; 
          for (var col in colKey) {
            var colKeyPair = new crypto.WeaveKeyPair();
            colKeyPair.cryptKey = forge.util.createBuffer(weave.util.Base64.decode(colKey[col][0]));
            colKeyPair.hmacKey  = forge.util.createBuffer(weave.util.Base64.decode(colKey[col][1]));
            self.bulkKeys[col] = colKeyPair;
          }
          weave.util.Log.info("Successfully decrypted bulk keys");

          if ( collection in self.bulkKeys )  {
            return P(self.bulkKeys['collection']);
          } else if ( 'default' in self.bulkKeys ) {
            weave.util.Log.info(sprintf("No key found for %s, using default", collection));
            return P(self.bulkKeys['default']);
          } else {
            throw new weave.error.WeaveError("No default key found");
          }
        });
      
	} else {
      if ( collection in this.bulkKeys )  {
        return P(this.bulkKeys['collection']);
      } else if ( 'default' in this.bulkKeys ) {
        weave.util.Log.info(sprintf("No key found for %s, using default", collection));
        return P(this.bulkKeys['default']);
      } else {
        throw new weave.error.WeaveError("No default key found");
      }
    }
    
  }
}

crypto.CryptoClientV5 = function() {
  crypto.CryptoClient.call(this);
}

crypto.CryptoClientV5.prototype = Object.create(crypto.CryptoClient.prototype);
crypto.CryptoClientV5.prototype.constructor = crypto.CryptoClientV5;

crypto.PayloadCipher = function() {

  return {
  decrypt: function(payload, keyPair) {
    weave.util.Log.debug("crypto.PayloadCipher.decrypt()");

	var cleartext     = null;
	var encryptObject = null;
	
    // Parse JSON encoded payload
	try {
	  encryptObject = JSON.parse(payload);
	} catch (e) {
	  throw new weave.error.WeaveError(e);
	}
    
    // An encrypted payload has three relevant fields
    var ciphertext  = encryptObject.ciphertext;
    var cipherbytes = weave.util.Base64.decode(ciphertext);
    var iv          = weave.util.Base64.decode(encryptObject.IV);
    var cipher_hmac = encryptObject.hmac;
    
    weave.util.Log.debug( sprintf("payload: %s, crypt key:  %s, crypt hmac: %s", payload, weave.util.Hex.encode(keyPair.cryptKey), weave.util.Hex.encode(keyPair.hmacKey)));
    
    
    // 1. Validate hmac of ciphertext
    // Note: HMAC verification is done against base64 encoded ciphertext
    var local_hmac = null;
    
    try {
      var hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', keyPair.hmacKey.bytes());
      hmacSHA256.update(ciphertext);
      local_hmac = hmacSHA256.digest().toHex();
	} catch (e) {
	  throw new weave.error.WeaveError(e);
	}
    
    if ( local_hmac !== cipher_hmac ) {
      weave.util.Log.warn(sprintf("cipher hmac: %s, local hmac: %s", cipher_hmac, local_hmac));
      throw new weave.error.WeaveError("HMAC verification failed!");
    }
    
    // 2. Decrypt ciphertext
    // Note: this is the same as this operation at the openssl command line:
    // openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`
    try {
      
      var cipher = forge.cipher.createDecipher('AES-CBC', keyPair.cryptKey.bytes()); ///PKCS5Padding");
      cipher.start({iv: iv});
      cipher.update(forge.util.createBuffer(cipherbytes));
      cipher.finish();
      cleartext = cipher.output.toString();

      weave.util.Log.debug(sprintf("cleartext: %s", cleartext));
      
	} catch (e) {
	  throw new weave.error.WeaveError(e);
    }
    
    weave.util.Log.info("Successfully decrypted v5 data record");
    
	return cleartext;
  },
  
  
  /**
   * encrypt()
   *
   * Given a plaintext object, encrypt it and return the ciphertext value.
   */
  encrypt: function(plaintext, keyPair) {
	weave.util.Log.debug("encrypt()");
	weave.util.Log.debug("plaintext:\n" + plaintext);
	
    weave.util.Log.debug(sprintf("payload: %s, crypt key:  %s, crypt hmac: %s", plaintext, weave.util.Hex.encode(keyPair.cryptKey), weave.util.Hex.encode(keyPair.hmacKey)));
	
	// Encryption primitives
    var ciphertext  = null;
    var cipherbytes = null;
    var iv          = null;
    var hmac        = null;
    
    // 1. Encrypt plaintext
    // Note: this is the same as this operation at the openssl command line:
    // openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`
	
    try {
      iv = forge.random.getBytesSync(16);
      
      var cipher = forge.cipher.createCipher('AES-CBC', keyPair.cryptKey.bytes());
      cipher.start({iv: iv});
      cipher.update(forge.util.createBuffer(plaintext));
      cipher.finish();
      cipherbytes = cipher.output;
      
      weave.util.Log.debug("ciphertext (hex): " + cipherbytes.toHex());
    
    } catch (e) {
	  throw new weave.error.WeaveError(e);
    }
    
    // 2. Create hmac of ciphertext
    // Note: HMAC is done against base64 encoded ciphertext
    ciphertext = weave.util.Base64.encode(cipherbytes.bytes());

    weave.util.Log.debug("ciphertext (base64): " + ciphertext);

    try {
      var hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', keyPair.hmacKey.bytes());
      hmacSHA256.update(ciphertext);
      hmac = hmacSHA256.digest();
      
	} catch (e) {
	  throw new weave.error.WeaveError(e);
	}
    
	weave.util.Log.info("Successfully encrypted v5 data record");
    
    // Construct JSONUtils encoded payload
	var encryptObject = {};
	encryptObject.ciphertext = ciphertext;
	encryptObject.IV         = weave.util.Base64.encode(iv);
	encryptObject.hmac       = weave.util.Hex.encode(hmac);
	
	return JSON.stringify(encryptObject);
  }	
  }
}();

crypto.HKDF = function() {

  return {

    /**
     * hkdf - The HMAC-based Key Derivation Function
     * based on https://github.com/mozilla/node-hkdf
     *
     * @class crypto.HKDF
     * @param {ByteBuffer} ikm Initial keying material
     * @param {ByteBuffer} info Key derivation data
     * @param {ByteBuffer} salt Salt
     * @param {integer} length Length of the derived key in bytes
     * @return promise object - It will resolve with `output` data
     */
    derive: function(ikm, info, salt, length) {
      
      // compute the PRK
      var prk = null;
      
      var mac = forge.hmac.create();
      mac.start('sha256', salt.bytes());
        
      mac.update(ikm.bytes());
      prk = mac.digest();

      // hash length is 32 because only sha256 is used at this moment
      var hashLength = 32;
      var num_blocks = Math.ceil(length / hashLength);
      var prev = forge.util.createBuffer();
      var output = forge.util.createBuffer();

      for (var i = 0; i < num_blocks; i++) {
        var hmac = forge.hmac.create();
        hmac.start('sha256', prk);

        var input = forge.util.createBuffer();
        input.putBytes(prev.bytes());
        input.putBytes(info.bytes());
        input.putBytes(forge.util.encodeUtf8(String.fromCharCode(i + 1)));

        hmac.update(input.bytes());
        prev = hmac.digest();
        
        output.putBytes(prev.bytes());
      }

      if ( output.length() > length ) {
        output.truncate(output.length() - length);
      }

      return P(output);
    }
  }
}();

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1,
 * as defined in FIPS PUB 180-1.
 *
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Modified by Anant Narayanan, 2008.
 *
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */
crypto.SHA1 = function () {
  /*
   * Configurable variables. You may need to tweak these to be compatible with
   * the server-side, but the defaults work in most cases.
   */
  var hexcase = 0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
  var b64pad  = "="; /* base-64 pad character. "=" for strict RFC compliance   */
  var chrsz   = 8;   /* bits per input character. 8 - ASCII; 16 - Unicode      */
  
  /*
   * Perform the appropriate triplet combination function for the current
   * iteration
   */
  function _ft_sha1(t, b, c, d) {
    if (t < 20) {
      return (b & c) | ((~b) & d);
    }
    if (t < 40) {
      return b ^ c ^ d;
    }
    if (t < 60) {
      return (b & c) | (b & d) | (c & d);
    }
    
    return b ^ c ^ d;
  }
  
  /*
   * Determine the appropriate additive constant for the current iteration
   */
  function _kt_sha1(t) {
    return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
           (t < 60) ? -1894007588 : -899497514;
  }
  
  /*
   * Add integers, wrapping at 2^32. This uses 16-bit operations internally
   * to work around bugs in some JS interpreters.
   */
  function _safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
  
  /*
   * Bitwise rotate a 32-bit number to the left.
   */
  function _rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  
  /*
   * Calculate the SHA-1 of an array of big-endian words, and a bit length
   */
  function _core_sha1(x, len) {
    /* append padding */
    x[len >> 5] |= 0x80 << (24 - len % 32);
    x[((len + 64 >> 9) << 4) + 15] = len;

    var w = new Array(80);
    var a =  1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d =  271733878;
    var e = -1009589776;

    for (var i = 0; i < x.length; i += 16) {
      var olda = a;
      var oldb = b;
      var oldc = c;
      var oldd = d;
      var olde = e;

      for (var j = 0; j < 80; j++) {
        if (j < 16) {
          w[j] = x[i + j];
        } else {
          w[j] = _rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
        }
        
        var t = _safe_add(_safe_add(_rol(a, 5), _ft_sha1(j, b, c, d)),
                          _safe_add(_safe_add(e, w[j]), _kt_sha1(j)));
        e = d;
        d = c;
        c = _rol(b, 30);
        b = a;
        a = t;
      }

      a = _safe_add(a, olda);
      b = _safe_add(b, oldb);
      c = _safe_add(c, oldc);
      d = _safe_add(d, oldd);
      e = _safe_add(e, olde);
    }
    
    return [a, b, c, d, e];
  }
  
  /*
   * Convert an 8-bit or 16-bit string to an array of big-endian words
   * In 8-bit function, characters >255 have their hi-byte silently ignored.
   */
  function _str2binb(str) {
    var bin = [];
    var mask = (1 << chrsz) - 1;
    
    for (var i = 0; i < str.length * chrsz; i += chrsz){
      bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
    }
    
    return bin;
  }

  /*
   * Convert an array of big-endian words to a string
   */
  function _binb2str(bin) {
    var str = "";
    var mask = (1 << chrsz) - 1;
    
    for (var i = 0; i < bin.length * 32; i += chrsz) {
      str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
    }
    
    return str;
  }

  /*
   * Convert an array of big-endian words to a hex string.
   */
  function _binb2hex(binarray) {
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    
    for (var i = 0; i < binarray.length * 4; i++) {
      str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
             hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
    }
    
    return str;
  }

  /*
   * Convert an array of big-endian words to a base-64 string
   */
  function _binb2b64(binarray) {
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str = "";
    
    for (var i = 0; i < binarray.length * 4; i += 3) {
      var triplet = (((binarray[i     >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                  | (((binarray[i + 1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                  |  ((binarray[i + 2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
      for (var j = 0; j < 4; j++) {
        if (i * 8 + j * 6 > binarray.length * 32) {
          str += b64pad;
        } else {
          str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
        }
      }
    }
    
    return str;
  }
  
  /*
   * Calculate the HMAC-SHA1 of a key and some data
   */
  function _core_hmac_sha1(key, data) {
    var bkey = _str2binb(key);
    if (bkey.length > 16) {
      bkey = _core_sha1(bkey, key.length * chrsz);
    }

    var ipad = new Array(16);
    var opad = new Array(16);
    for (var i = 0; i < 16; i++) {
      ipad[i] = bkey[i] ^ 0x36363636;
      opad[i] = bkey[i] ^ 0x5C5C5C5C;
    }

    var hash = _core_sha1(ipad.concat(_str2binb(data)), 512 + data.length * chrsz);
    return _core_sha1(opad.concat(hash), 512 + 160);
  }
  
  return {
    digest: function(s, t) {
      switch (t) {
        case 2:
          return _binb2str(_core_sha1(_str2binb(s), s.length * chrsz));
        case 3:
          return _binb2b64(_core_sha1(_str2binb(s), s.length * chrsz));
        default:
          return _binb2hex(_core_sha1(_str2binb(s), s.length * chrsz));
      }
    },
    
    hmac: function(key, data, t) {
      switch (t) {
        case 2:
          return _binb2b64(_core_hmac_sha1(key, data));
        case 3:
          return _binb2str(_core_hmac_sha1(key, data));
        default:
          return _binb2hex(_core_hmac_sha1(key, data));
      }
    }
  };
  
}();

module.exports = crypto;
