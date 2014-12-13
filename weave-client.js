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

//nodejs includes
var util = require('util');

//npm includes
var sprintf = require('sprintf');
var URI     = require('URIjs');
var forge   = require('node-forge');

//other third party includes
//var JSON = require('./lib/json2');

//app includes
var weave = require('./weave-include');
require('./weave-net');
require('./weave-crypto');
require('./weave-util');

weave.client = {};

weave.client.WeaveBasicObject = function() {  
  this.id        = null;
  this.modified  = null;
  this.sortindex = null;
  this.ttl       = null;
  this.payload   = null;
}

weave.client.WeaveBasicObject.prototype = {
  getPayloadAsJSONObject: function() {
    weave.Log.debug("weave.client.WeaveBasicObject.getPayloadAsJSONObject()");
    return JSON.parse(this.payload);
  }
};

weave.client.WeaveClient = function() {
  var account       = null;
  var storageClient = null;
  var regClient     = null;
  var privateKey    = null;
  var bulkKeys      = null;
}

weave.client.WeaveClient.prototype = {

  KEY_CRYPTO_PATH:       "crypto/keys",
  KEY_CRYPTO_COLLECTION: "crypto",
  KEY_CRYPTO_ID:         "keys",
  KEY_META_PATH:         "meta/global",
  KEY_META_COLLECTION:   "meta",
  KEY_META_ID:           "global",
  
  init: function(baseURL, user, password, syncKey) {
	this.privateKey      = null;
	this.bulkKeys        = null;
    
	//Store account params
	this.account = {};
	this.account.baseURL  = baseURL;
	this.account.user     = user;
	this.account.password = password;
	this.account.syncKey  = syncKey;
	
	//Initialise registration and storage clients with account details
	this.regClient = new weave.client.RegistrationApi();
	this.regClient.init(baseURL, user, password);
	this.storageClient = new weave.client.StorageApi();
	this.storageClient.init(this.regClient.getStorageUrl(), user, password);
  },
  
  isEncrypted: function(wbo) {
	//Determine if WBO is encrypted or not
	var jsonPayload  = wbo.getPayloadAsJSONObject();
	return ( 'ciphertext' in jsonPayload &&  'IV' in jsonPayload && 'hmac' in jsonPayload );
  },

  /**
   * Fetch the private key for the user and storage context
   * provided to this object, and decrypt the private key
   * by using my passphrase.  Store the private key in internal
   * storage for later use.
   */
  getPrivateKeyPair: function() {
	weave.Log.debug("weave.client.WeaveClient.getPrivateKeyPair()");

	if ( this.privateKey === null ) {
      
	  // Generate key pair using SHA-256 HMAC-based HKDF of sync key
	  // See https://docs.services.mozilla.com/sync/storageformat5.html#the-sync-key
      
	  // Remove dash chars, convert to uppercase and translate 8 and 9 to L and O
	  var syncKeyB32 = this.account.syncKey.toUpperCase()
		.replace('8', 'L', 'g')
		.replace('9', 'O', 'g')
		.replace("-", "", 'g');

	  weave.Log.debug(sprintf("normalised sync key: %s",  syncKeyB32));

	  // Pad base32 string to multiple of 8 chars (40 bits)
	  if ( (syncKeyB32.length % 8) > 0 ) {
		var paddedLength = syncKeyB32.length + 8 - (syncKeyB32.length % 8);
		syncKeyB32 = weave.util.StringUtils.rightPad(syncKeyB32, paddedLength, '=');
	  }

	  var syncKeyBin = weave.util.Base32.decode(syncKeyB32);

      var keyInfo = "Sync-AES_256_CBC-HMAC256" + this.account.user;

	  // For testing only
	  //syncKeyBin = weave.util.Hex.decode("c71aa7cbd8b82a8ff6eda55c39479fd2")
	  //keyInfo = "Sync-AES_256_CBC-HMAC256" + "johndoe@example.com"

	  weave.Log.debug(sprintf("base32 key: %s decoded to %s", this.account.syncKey, weave.util.Hex.encode(syncKeyBin)));

	  var keyPair = new weave.crypto.WeaveKeyPair();

      var hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.UTF8.encode(keyInfo + "\x01"));
	  keyPair.cryptKey = hmacSHA256.digest();

      hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.BinUtils.binConcat(keyPair.cryptKey, weave.util.UTF8.encode(keyInfo + "\x02")));
	  keyPair.hmacKey = hmacSHA256.digest();
	  
	  this.privateKey = keyPair;
	  
	  weave.Log.info("Successfully generated sync key and hmac key");
	  weave.Log.debug(sprintf("sync key: %s, crypt key: %s, crypt hmac: %s", this.account.syncKey, weave.util.Hex.encode(keyPair.cryptKey), weave.util.Hex.encode(keyPair.hmacKey)));
	}
    
	return this.privateKey;
  },

  /**
   * Given a bulk key label, pull the key down from the network,
   * and decrypt it using my private key.  Then store the key
   * into self storage for later decrypt operations.
   */
  getBulkKeyPair: function(collection) {
	weave.Log.debug("weave.client.WeaveClient.getBulkKeyPair()");
	
	if ( this.bulkKeys === null ) {
	  weave.Log.info("Fetching bulk keys from server");
      
      varres = null;
      try {
        res = this.storageClient.get(this.KEY_CRYPTO_PATH);
      } catch (e) {
        throw new weave.WeaveError(e.message);
      }

      // Recursively call decrypt to extract key data
      var payload = this.decrypt(res.payload, null);            
      var keyData = JSON.parse(payload);

      this.bulkKeys   = {};
      
      //Get default key pair
      var defaultKey = keyData['default'];
      
      var keyPair = new weave.crypto.WeaveKeyPair();
      keyPair.cryptKey = weave.util.Base64.decode(defaultKey[0]);
      keyPair.hmacKey  = weave.util.Base64.decode(defaultKey[1]);
      this.bulkKeys['default'] = keyPair;
      
      //Get collection key pairs
      var colKey = keyData['collections']; 
      for (var col in colKey) {
        var colKeyPair = new weave.crypto.WeaveKeyPair();
        colKeyPair.cryptKey = weave.util.Base64.decode(colKey[col][0]);
        colKeyPair.hmacKey  = weave.util.Base64.decode(colKey[col][1]);
        this.bulkKeys[col] = colKeyPair;
      }
      
      weave.Log.info(sprintf("Successfully decrypted bulk key for %s", collection));
	}

    if ( collection in this.bulkKeys )  {
      return this.bulkKeys['collection'];
    } else if ( 'default' in this.bulkKeys ) {
      weave.Log.info(sprintf("No key found for %s, using default", collection));
      return this.bulkKeys['default'];      	
    } else {
      throw new weav.WeaveError("No default key found");
    }
  },
  
  decryptWeaveBasicObject: function(encWbo, collection) {
    weave.Log.debug("weave.client.WeaveClient.decryptWeaveBasicObject()");

	if ( !this.isEncrypted(encWbo) ) {
	  throw new weave.WeaveError("Weave Basic Object already decrypted");
	}
    
    var decWbo = new weave.client.WeaveBasicObject();
    
	decWbo.id         = encWbo.id
	decWbo.modified   = encWbo.modified;
	decWbo.sortindex  = encWbo.sortindex;
	decWbo.payload    = this.decrypt(encWbo.payload, collection);
	decWbo.ttl        = encWbo.ttl;
    
    return decWbo;
  },
  
  decrypt: function(payload, collection) {
    weave.Log.debug("weave.client.WeaveClient.decrypt()");
    
    var keyPair = new weave.crypto.WeaveKeyPair();
    
    if ( collection === null ) {
      weave.Log.info("Decrypting data record using sync key");
      
      try {
        keyPair = this.getPrivateKeyPair();
      } catch(e){
        throw new weave.WeaveError(e.message);
      }
      
    } else {
      weave.Log.info(sprintf("Decrypting data record using bulk key %s", collection));
      
      keyPair = this.getBulkKeyPair(collection);
    }
    
    var cipher = new weave.crypto.PayloadCipher();
    
    return cipher.decrypt(payload, keyPair);
  },
    
  get: function(collection, id, decrypt) {
    weave.Log.debug("weave.client.WeaveClient.get()");

    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

	var wbo = this.storageClient.get(collection, id);
    
    if (decrypt) {
	  wbo = this.decryptWeaveBasicObject(wbo, collection);
    }
    return wbo;
  },

  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, decrypt) {
    weave.Log.debug("weave.client.WeaveClient.getCollection()");

    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

	var wbos = this.storageClient.getCollection(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format);

    if (decrypt) {
      var decWbos = [];
      for (var i = 0; i < wbos.length; i++) {
	    decWbos.push(this.decryptWeaveBasicObject(wbos[i], collection));
      }
      wbos = decWbos;
    }
    return wbos;
  }

};

weave.client.RegistrationApi = function() {
  var baseURL  = null;
  var user     = null;
  var password = null;
};

weave.client.RegistrationApi.prototype = {  

  init: function(baseURL, user, password) {
    this.baseURL  = baseURL;
	this.user     = user;
	this.password = password;
  },
  
  getStorageUrl: function() {
      
	//TODO - confirm account exists, i.e. /user/1.0/USER returns 1
		
	var url = URI(sprintf("user/1.0/%s/node/weave", this.user)).absoluteTo(this.baseURL);

	return weave.net.Http.get(url, 2000);
  }
};

weave.client.StorageApi = function() {
  var storageURL;
  var user;
  var password;
};

weave.client.StorageApi.prototype = {

  init: function(storageURL, user, password) {
    weave.Log.debug("weave.client.StorageApi.init()");

    this.storageURL = storageURL;
    this.user       = user;
    this.password   = password;

    weave.net.Http.setCredentials({username: user, password: password});
  },

  get: function(collection, id) {
	weave.Log.debug("get()");

    var path = null;
    if (typeof id !== 'undefined') {
      //build path from collection and id
      path = collection + "/" + id;
    } else {
      //assume first arg is path
      path = collection;
    }

    var url = this.buildStorageUri(path);
	var response = weave.net.Http.get(url, 2000);
    var jsonObject = JSON.parse(response);

    var wbo = new weave.client.WeaveBasicObject();
	wbo.id         = jsonObject.id
	wbo.modified   = jsonObject.modified;
	wbo.sortindex  = jsonObject.sortindex;
	wbo.payload    = jsonObject.payload;
	wbo.ttl        = jsonObject.ttl;

    return wbo;
  },
  
  buildStorageUri: function(path) {
	//return URI(sprintf("1.1/%s/storage/%s", this.user, path)).absoluteTo(this.storageURL).username(this.user).password(this.password);
	return URI(sprintf("1.1/%s/storage/%s", this.user, path)).absoluteTo(this.storageURL);
  },

  buildCollectionUri: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, full) {

	var params = {};

	if ( ids !== null && ids.length > 0 ) {
      params['ids'] = ids.join(',');
	}
	if (older !== null) {
	  params['older'] = sprintf("%.2f", older);
	}
	if (newer !== null) {
	  params['newer'] = sprintf("%.2f", newer);
	}
	if (index_above !== null) {
	  params['index_above'] = index_above;
	}
	if (index_below !== null) {
	  params['index_below'] = index_below;
	}
	if (limit !== null) {
	  params['limit'] = limit;
	}
	if (offset !== null) {
	  params['offset'] = offset;
	}
	if (sort !== null) {
	  if ( sort.match(/^oldest|newest|index$/i) ) {
		params['sort'] = sort;
	  } else {
		throw new weave.WeaveError(sprintf("buildCollectionUri() sort parameter value of '%s' not recognised", sort));
	  }
	}
	if (format !== null) {
	  //Only default format supported
	  throw new weave.WeaveError(sprintf("buildCollectionUri() format parameter value of '%s' not supported", format));
	}
	if ( full ) {
	  //returns entire WBO
	  params['full'] = "1";
	}

	return URI(this.buildStorageUri(collection)).query(params);
  },
  
  getCollectionIds: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort) {
    weave.Log.debug("weave.client.WeaveStorageApi.getCollectionIds()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, null, false);

	var response = weave.net.Http.get(url, 2000);
    var ids = JSON.parse(response);

    return ids;
  },
  
  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format) {
    weave.Log.debug("weave.client.WeaveStorageApi.getCollection()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, true);

	var response = weave.net.Http.get(url, 2000);
    var jsonArray = JSON.parse(response);

    var wbos = [];
    for (var i = 0; i < jsonArray.length; i++) {
      var jsonObject = jsonArray[i];
      var wbo = new weave.client.WeaveBasicObject();
	  wbo.id         = jsonObject.id
	  wbo.modified   = jsonObject.modified;
	  wbo.sortindex  = jsonObject.sortindex;
	  wbo.payload    = jsonObject.payload;
	  wbo.ttl        = jsonObject.ttl;

      wbos.push(wbo);
    }
    
    return wbos;
  }
  
};
