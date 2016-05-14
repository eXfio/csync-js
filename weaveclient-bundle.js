(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.weave = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (global){
/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave Sync client supporting Storage Data v5 and Storage API 
 *  v1.1 and v1.5
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
var FxAccountClient = (typeof window !== "undefined" ? window['FxAccountClient'] : typeof global !== "undefined" ? global['FxAccountClient'] : null);
var P   = require('p-promise');
var jwcrypto = (typeof window !== "undefined" ? window['jwcrypto'] : typeof global !== "undefined" ? global['jwcrypto'] : null);
require("browserid-crypto/lib/algs/ds");
var URI = require('URIjs');
var sprintf = require('sprintf');
var forge = (typeof window !== "undefined" ? window['forge'] : typeof global !== "undefined" ? global['forge'] : null);

//app includes
var weave = {};
weave.error  = require('../weave-error');
weave.util   = require('../weave-util');
weave.net    = require('../weave-net');
weave.crypto = require('../weave-crypto');

var fxAccount = {};

fxAccount.FxAccount = function() {
  this.storageApiVersion = "v1_5";
  this.cryptoApiVersion  = "v5";

  this.fxaClient     = null;
  this.accountServer = null;
  this.tokenServer   = null

  //To instantiate FxAccount user and passsword OR fxaSession and kB are required
  this.user          = null;
  this.password      = null;

  this.fxaSession    = null;
  this.kB            = null;

  this.syncToken     = null;
  this.keyPair       = null;
};

fxAccount.FxAccount.prototype = {  

  'DEFAULT_CERTIFICATE_DURATION_IN_MILLISECONDS': 60 * 60 * 1000,
  'DEFAULT_ASSERTION_DURATION_IN_MILLISECONDS': 60 * 60 * 1000,
  'DEFAULT_FUTURE_EXPIRES_AT_IN_MILLISECONDS': 9999999999999,
  'DEFAULT_CERTIFICATE_ISSUER': "127.0.0.1",
  'DEFAULT_ASSERTION_ISSUER': "127.0.0.1",

  'TOKEN_SERVER_HEADER_BROWSERID_AUTH': "Authorization",
  'TOKEN_SERVER_HEADER_CLIENT_STATE': "X-Client-State",

  init: function(params, config) {
    weave.util.Log.debug("FxAccount.init()");

    weave.util.Log.debug("params: " + JSON.stringify(params));
    
    //Handle defaults
    if (!config) {
      config = {};
    }

    if ( typeof XMLHttpRequest === 'undefined' && typeof config.xhr === 'undefined' ) {
      config.xhr = require("xmlhttprequest").XMLHttpRequest;
    }

    this.accountServer = params.accountServer;
    this.tokenServer   = params.tokenServer;
    this.fxaClient     = new FxAccountClient(this.accountServer, config);

    var self = this;

    //First make sure we have a valid FxA sessionToken
    var sessionPromise = null;
    
    if ( params.sessionToken && params.kB ) {
      this.fxaSession = params.sessionToken;
      this.kB         = params.kB;
      sessionPromise = P(true);
    } else if ( params.user && params.password ) {
	  this.user     = params.user;
	  this.password = params.password;

      sessionPromise = this.initSession()
        .then(function() {
          return self.getKeys();
        });
    } else {
      sessionPromise = P.reject("user and passsword OR sessionToken and kB are required parameters");
    }
    
    return sessionPromise
	  .then(function() {
        return self.getSyncAuthToken();
      })
      .then(function() {
        return self.getMasterKeyPair()
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't initialise FxA account - " + error);
        return P.reject(error);
      });
  },
  
  isInitialized: function() {
    return ( this.syncToken !== null );
  },
  
  getStorageParams: function() {
    return {
      apiVersion: this.storageApiVersion,
      storageURL: this.getStorageUrl(),
	  user:       this.user,
	  hawkid:     this.syncToken.id,
	  hawkkey:    this.syncToken.key
    };
  },

  getCryptoParams: function() {
    return {
      apiVersion: this.cryptoApiVersion,
      keyPair:    this.keyPair
    };      
  },

  getStorageUrl: function() {
    return this.syncToken.api_endpoint;
  },

  generateBrowserIdKeyPair: function() {
    weave.util.Log.debug("generateBrowserIdKeyPair()");
    
    var deferred = P.defer();
    
    jwcrypto.generateKeypair(
      {
        algorithm: 'DSA',
        keysize: 128
      },
      function(err, keypair) {
        // error in err?
        
        if (err) {
          weave.util.Log.error("Couldn't generate key pair - " + err);
          deferred.reject(err);
        } else {
          deferred.resolve(keypair);
        }
      }
    );

    return deferred.promise;
  },

  //Derive client state - 16 bytes of sha256 digest hex encoded
  deriveClientState: function() {
    var md = forge.md.sha256.create();
    md.update(this.kB.bytes());
    var kBDigest = md.digest();
    kBDigest.truncate(kBDigest.length() - 16);
    return kBDigest.toHex();
  },

  /**
   * build browserid assertion then request sync auth token from token server
   *
   * GET /1.0/sync/1.5
   * Host: token.services.mozilla.com
   * Authorization: BrowserID <assertion>
   * 
   * The sync auth token is a JSON object with the following attributes
   * {
   *   "uid": 16999487, //FirefoxSync ID
   *   "hashalg": "sha256",
   *   "api_endpoint": "https://sync-176-us-west-2.sync.services.mozilla.com/1.5/16999487", //FirefoxSync storage endpoint
   *   "key": "G_QwGbDXc6aYtXVrhmO5-ymQZbyZQoES8q75a-eFyik=", //Hawk auth key. NOTE: DO NOT decode
   *   "id": "eyJub2RlIjogImh0dHBzOi8vc3luYy0xNzYtdXMtd2VzdC0yLnN5bmMuc2VydmljZXMubW96aWxsYS5jb20iLCAiZXhwaXJlcyI6IDE0MjIyNTQzNTMsICJzYWx0IjogIjdiYTQ0YyIsICJ1aWQiOiAxNjk5OTQ4N32olTf0a2mlUz9BezgYVASI_4hQ8nEl6VZVFM5RbwmQmA==" //Hawk auth id. NOTE: DO NOT decode
   *   "duration": 3600,
   * }
   * 
   */
  getSyncAuthToken: function(audience) {
	weave.util.Log.debug("getSyncAuthToken()");

    var self = this;
    
    //Default values
    if ( audience === undefined ) {
      //strip path and query string from URL
      var uri = URI(this.tokenServer);
      audience = URI.build({
        protocol: uri.scheme(),
        hostname: uri.hostname(),
        port: uri.port()
      });
    }

	this.syncToken = null;
      
	//Get browserid certificate
    return this.getCertificate()
      .then(function(browserIdCertificate) {
        //Build assertion
        return self.buildAssertion(browserIdCertificate.keyPair, browserIdCertificate.certificate, audience);
      })
      .then(function(assertion) {
        var clientState = self.deriveClientState();
        
	    //Request sync token
	    return self.getTokenFromBrowserIDAssertion(assertion, clientState);
      })
      .then(function(token) {
        weave.util.Log.debug("Sync token: " + JSON.stringify(token));
        
        self.syncToken = token;
	    return P(token);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get sync token - " + error);
        return P.reject(error);
      });
  },
  
  initSession: function(force) {
    weave.util.Log.debug("initSession()");

    var self = this;

    force = force || false;
    
    if (force && this.fxaSession != null) {
      weave.util.Log.debug("Destroy FxA session");

      return this.fxaClient.sessionDestroy(this.fxaSession)
        .then(
          function() {
            self.fxaSession = null;
            return self.initSession();
          },
          function(error) {
            weave.util.Log.warn("Couldn't destroy FxA session - " + error);
            self.fxaSession = null;
            return self.initSession();
          }
        )
    }

    //TODO - check expiration date of FxA session token
    if ( this.fxaSession != null ) {
      weave.util.Log.debug("Valid FxA session, continue");
      return P(this.fxaSession);
    } else {
      weave.util.Log.debug("Calling fxaClient.signIn()");
	  return this.fxaClient.signIn(this.user, this.password, {keys: true})
        .then(
          function(fxaSession) {
            weave.util.Log.debug("FxA session: " + JSON.stringify(fxaSession));
            self.fxaSession = fxaSession;
            return P(self.fxaSession);
          },
          function(error) {
            weave.util.Log.error("Couldn't initiate FxA session - " + error);
            return P.reject(error);
          }
        );
    }
  },
  
  getKeys: function() {
    weave.util.Log.debug("getKeys()");
    
    var self = this;
    
	return self.fxaClient.accountKeys(self.fxaSession.keyFetchToken, self.fxaSession.unwrapBKey)
      .then(function(fxaKeys) {
        weave.util.Log.debug(sprintf("kA: %s, kB: %s", fxaKeys.kA, fxaKeys.kB));
        self.kB = forge.util.createBuffer(weave.util.Hex.decode(fxaKeys.kB));
        return P(fxaKeys);
      })
      .fail(function(error) {
	    weave.util.Log.error("Couldn't get FxA keys - " + error);
        return R.reject(error);
	  });
  },
  
  getCertificate: function() {
	weave.util.Log.debug("getCertificate()");

	var self = this;

    var browserIdKeyPair = null;
    var browserIdCertificate = null;
    
	//Mozilla Android app used duration of 12 * 60 * 60 * 1000
	//long certificateDuration = 5 * 60 * 1000; //5minutes
	var certificateDuration = 12 * 60 * 60 * 1000; //12 hours
    
    //Generate BrowserID KeyPair
	return self.generateBrowserIdKeyPair()
      .then(function(keyPair) {
        browserIdKeyPair = keyPair;          
	    return self.fxaClient.certificateSign(self.fxaSession.sessionToken, browserIdKeyPair.publicKey.serialize(), certificateDuration);
      })
      .then(function(certificate) {
        browserIdCertificate = {
          keyPair: browserIdKeyPair,
          certificate: certificate.cert
        };
        return P(browserIdCertificate);
      })
	  .fail(function(error) {
        weave.util.Log.error("Couldn't get FxA BrowserID certificate - " + JSON.stringify(error));
        return P.reject(error);
      });
  },
  
  buildAssertion: function(keyPair, certificate, audience, issuer) {
	weave.util.Log.debug("buildAssertion()");

    var deferred = P.defer();

    if ( issuer === undefined ) {
      //issuer = this.DEFAULT_ASSERTION_ISSUER;
      issuer = "127.0.0.1";
    }
    
	// We generate assertions with no iat and an exp after 2050 to avoid
	// invalid-timestamp errors from the token server.
    //var curDate = new Date();
    //var expiresAt = curDate.getTime() + (60 * 60 * 1000);
	//var expiresAt = this.DEFAULT_FUTURE_EXPIRES_AT_IN_MILLISECONDS;
    var expiresAt = 9999999999999;
            
    var payload = {
      aud: audience,
      exp: expiresAt,
      iss: issuer
    };

    jwcrypto.sign(
      payload,
      keyPair.secretKey,
      function(err, signedAssertion) {
        if (err) {
          deferred.reject(err);
        } else {
          deferred.resolve(certificate + "~" + signedAssertion);
        }
      }
    );

    return deferred.promise;
  },

  getTokenFromBrowserIDAssertion: function(assertion, clientState) {
    weave.util.Log.debug("getTokenFromBrowserIDAssertion()");
    
    var self = this;
    
    headers = {
      'X-Client-State': clientState
    };

    var httpClient = new weave.net.HttpClient();
    httpClient.setAuthProvider(new weave.net.BrowserIdAuthProvider({'assertion': assertion}));

    return httpClient.asyncGet(this.tokenServer, 5000, headers)
      .then(
        function(response) {
          //Try to parse json
          var result = response;
          try {
            result = JSON.parse(response);
          } catch(e) {}
          return P(result);
        },
        function(error) {
          weave.util.Log.error("Token server request failed - " + error);
          return P.reject(error);
          
          /*
          // The service shouldn't have any 3xx, so we don't need to handle those.
          if (res.getStatusCode() != 200) {
            // We should have a (Cornice) error report in the JSON. We log that to
            // help with debugging.
            List<ExtendedJSONObject> errorList = new ArrayList<ExtendedJSONObject>();

            if (result.containsKey(JSON_KEY_ERRORS)) {
              try {
                for (Object error : result.getArray(JSON_KEY_ERRORS)) {
                  Logger.warn(LOG_TAG, "" + error);
                  
                  if (error instanceof JSONObject) {
                    errorList.add(new ExtendedJSONObject((JSONObject) error));
                  }
                }
              } catch (NonArrayJSONException e) {
                Logger.warn(LOG_TAG, "Got non-JSON array '" + result.getString(JSON_KEY_ERRORS) + "'.", e);
              }
            }
            
            if (statusCode == 400) {
              throw new TokenServerMalformedRequestException(errorList, result.toJSONString());
            }
            
            if (statusCode == 401) {
              throw new TokenServerInvalidCredentialsException(errorList, result.toJSONString());
            }
            
            // 403 should represent a "condition acceptance needed" response.
            //
            // The extra validation of "urls" is important. We don't want to signal
            // conditions required unless we are absolutely sure that is what the
            // server is asking for.
            if (statusCode == 403) {
              // Bug 792674 and Bug 783598: make this testing simpler. For now, we
              // check that errors is an array, and take any condition_urls from the
              // first element.
              
              try {
                if (errorList == null || errorList.isEmpty()) {
                  throw new TokenServerMalformedResponseException(errorList, "403 response without proper fields.");
                }
                
                ExtendedJSONObject error = errorList.get(0);
                
                ExtendedJSONObject condition_urls = error.getObject(JSON_KEY_CONDITION_URLS);
                if (condition_urls != null) {
                  throw new TokenServerConditionsRequiredException(condition_urls);
                }
              } catch (NonObjectJSONException e) {
                Logger.warn(LOG_TAG, "Got non-JSON error object.");
              }
              
              throw new TokenServerMalformedResponseException(errorList, "403 response without proper fields.");
            }
            
            if (statusCode == 404) {
              throw new TokenServerUnknownServiceException(errorList);
            }
            
            // We shouldn't ever get here...
            throw new TokenServerException(errorList);
            */
        }

      );
  },


  /**
   * Derive the key pair from kB
   */
  getMasterKeyPair: function() {
	weave.util.Log.debug("FxAccount.getMasterKeyPair()");

    var self = this;
    
	if ( this.keyPair !== null ) {
      return P(this.keyPair);
    } else {
    
      //TODO - handle case where kB is not initialised

      var info = forge.util.createBuffer("identity.mozilla.com/picl/v1/oldsync");
      var salt = forge.util.createBuffer();
      
      return weave.crypto.HKDF.derive(
        this.kB,
        info,
        salt,
        2*32
      ).then(
        function(derived) {
          self.keyPair = {
	        cryptKey: forge.util.createBuffer(derived.getBytes(32)),
	        hmacKey:  forge.util.createBuffer(derived.getBytes())
          };
	  
	      weave.util.Log.info("Successfully generated key pair");
	      weave.util.Log.debug(sprintf("kB: %s, crypt key: %s, hmac key: %s", self.kB.toHex(), self.keyPair.cryptKey.toHex(), self.keyPair.hmacKey.toHex()));
          
          return P(self.keyPair);
        },
        function(error) {
          weave.util.Log.error("Couldn't generate key pair - " + error);
          return P.reject(error);
        }
      );
	}
    
  }
  
};

module.exports = fxAccount;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../weave-crypto":4,"../weave-error":5,"../weave-net":6,"../weave-util":8,"URIjs":11,"browserid-crypto/lib/algs/ds":13,"p-promise":16,"sprintf":18,"xmlhttprequest":undefined}],2:[function(require,module,exports){
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
var P   = require('p-promise');

//app includes
var weave = {};
weave.error  = require('../weave-error');
weave.util   = require('../weave-util');
weave.net    = require('../weave-net');
weave.crypto = require('../weave-crypto');

var legacyAccount = {};

legacyAccount.LegacyAccount = function() {
  var storageApiVersion = "v1_1";
  var cryptoApiVersion  = "v5";

  var baseURL  = null;
  var user     = null;
  var password = null;
  var syncKey  = null;

  var storageUrl = null;
  var keyPair    = null;
};

legacyAccount.LegacyAccount.prototype = {  

  init: function(params) {
    this.baseURL  = params.baseURL;
	this.user     = params.user;
	this.password = params.password;
    this.syncKey  = params.syncKey;

    this.getStorageUrl();
    this.getMasterKeyPair();

    return P(true);
  },

  getStorageParams: function() {
    return {
      apiVersion: this.storageApiVersion,
      storageURL: this.storageUrl,
	  user:       this.user,
	  password:   this.password
    };
  },

  getCryptoParams: function() {
    return {
      apiVersion: this.cryptoApiVersion,
      keyPair:    this.keyPair
    };      
  },

  getStorageUrl: function() {
    
    if ( this.storageUrl == null ) {  
	  //TODO - confirm account exists, i.e. /user/1.0/USER returns 1
		
	  var url = URI(sprintf("user/1.0/%s/node/weave", this.user)).absoluteTo(this.baseURL);

	  this.storageUrl = weave.net.Http.get(url, 2000);
    }
    
    return this.storageUrl;
  },

  /**
   * Derive the key pair from the base32 sync key
   */
  getMasterKeyPair: function() {
	weave.util.Log.debug("weave.client.WeaveClient.getPrivateKeyPair()");

	if ( this.keyPair === null ) {
      
	  // Generate key pair using SHA-256 HMAC-based HKDF of sync key
	  // See https://docs.services.mozilla.com/sync/storageformat5.html#the-sync-key
      
	  // Remove dash chars, convert to uppercase and translate 8 and 9 to L and O
	  var syncKeyB32 = this.syncKey.toUpperCase()
		.replace('8', 'L', 'g')
		.replace('9', 'O', 'g')
		.replace("-", "", 'g');

	  weave.util.Log.debug(sprintf("normalised sync key: %s",  syncKeyB32));

	  // Pad base32 string to multiple of 8 chars (40 bits)
	  if ( (syncKeyB32.length % 8) > 0 ) {
		var paddedLength = syncKeyB32.length + 8 - (syncKeyB32.length % 8);
		syncKeyB32 = weave.util.StringUtils.rightPad(syncKeyB32, paddedLength, '=');
	  }

	  var syncKeyBin = weave.util.Base32.decode(syncKeyB32);

      var keyInfo = "Sync-AES_256_CBC-HMAC256" + this.user;

	  // For testing only
	  //syncKeyBin = weave.util.Hex.decode("c71aa7cbd8b82a8ff6eda55c39479fd2")
	  //keyInfo = "Sync-AES_256_CBC-HMAC256" + "johndoe@example.com"

	  weave.util.Log.debug(sprintf("base32 key: %s decoded to %s", this.syncKey, weave.util.Hex.encode(syncKeyBin)));

	  var keyPair = new weave.crypto.WeaveKeyPair();

      var hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.UTF8.encode(keyInfo + "\x01"));
	  keyPair.cryptKey = hmacSHA256.digest();

      hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.BinUtils.binConcat(keyPair.cryptKey, weave.util.UTF8.encode(keyInfo + "\x02")));
	  keyPair.hmacKey = hmacSHA256.digest();
	  
	  weave.util.Log.info("Successfully generated sync key and hmac key");
	  weave.util.Log.debug(sprintf("sync key: %s, crypt key: %s, crypt hmac: %s", this.syncKey, weave.util.Hex.encode(keyPair.cryptKey), weave.util.Hex.encode(keyPair.hmacKey)));

      this.keyPair = keyPair;
	}

	return this.keyPair;
  }

};

module.exports = legacyAccount;

},{"../weave-crypto":4,"../weave-error":5,"../weave-net":6,"../weave-util":8,"p-promise":16}],3:[function(require,module,exports){
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
var P = require('p-promise');
var sprintf = require('sprintf');

//app includes
var weave = {};
weave.error   = require('./weave-error');
weave.util    = require('./weave-util');
weave.storage = require('./weave-storage');
weave.crypto  = require('./weave-crypto');

var baseClient = {};

baseClient.WeaveClientFactory = (function() {
  return {
    getInstance: function(account) {
      var weaveClient = new baseClient.WeaveClient();
	  weaveClient.init(account);
	  return weaveClient;
    }
  };
})();

baseClient.WeaveClient = function() {
  this.accountClient = null;
  this.storageClient = null;
  this.crytoClient   = null;  
}

baseClient.WeaveClient.prototype = {

  init: function(account) {
    weave.util.Log.debug("WeaveClient.init()");
    this.accountClient = account;
    this.storageClient = weave.storage.StorageClientFactory.getInstance(this.accountClient.getStorageParams());
    this.cryptoClient = weave.crypto.CryptoClientFactory.getInstance(this.storageClient, this.accountClient.getCryptoParams());    
  },

  initStorageAndCrypto: function() {
    var self = this;
    return this.accountClient.getSyncAuthToken()
      .then(function() {
        self.storageClient.init(self.accountClient.getStorageParams());
        self.cryptoClient.init(self.storageClient, self.accountClient.getCryptoParams());
        return P(true);
      });
  },
  
  isInitialized: function() {
    return (typeof this.accountClient === 'object' && typeof this.storageClient === 'object' && typeof this.cryptoClient === 'object');
  },

  get: function(collection, id, decrypt, isRetry) {
    weave.util.Log.debug("WeaveClient.get()");

    var self = this;
    
    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);
    isRetry = (typeof isRetry !== 'undefined' ? isRetry : false);

    return this.storageClient.get(collection, id)
      .then(function(wbo) {
        if (decrypt) {
	      return self.cryptoClient.decryptWeaveBasicObject(wbo, collection);
        }
        return P(wbo);
      })
      .fail(function(error) {
        if ( !isRetry && error.match(/401\s+unauthorized/i) ) {
          weave.util.Log.warn("Request unauthorized - requesting new sync token");
          return self.initStorageAndCrypto()
            .then(function() {
              return self.get(collection, id, decrypt, true)
            });
        } else {
          weave.util.Log.error("Couldn't get weave item - " + error);
          return P.reject(error);
        }
      });
  },

  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, decrypt, isRetry) {
    weave.util.Log.debug("WeaveClient.getCollection()");

    var self = this;
    
    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);
    isRetry = (typeof isRetry !== 'undefined' ? isRetry : false);

	return this.storageClient.getCollection(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format)
      .then(function(wbos) {
        if (decrypt) {
          var decPromise = [];
          for (var i = 0; i < wbos.length; i++) {
            decPromise.push(self.cryptoClient.decryptWeaveBasicObject(wbos[i], collection));
          }
          return P.all(decPromise)
            .then(function(decWbos) {
              return P(decWbos);
            });
        }
        return P(wbos);
      })
      .fail(function(error) {
        if ( !isRetry && error.match(/401\s+unauthorized/i) ) {
          weave.util.Log.warn("Request unauthorized - requesting new sync token");
          return self.initStorageAndCrypto()
            .then(function() {
              return self.getCollection(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, decrypt, true)
            });
        } else {
          weave.util.Log.error("Couldn't get weave collection - " + error);
          return P.reject(error);
        }
      });
  },

  put: function(collection, id, wbo, encrypt) {
    weave.util.Log.debug("WeaveClient.put()");

    var self = this;
    
    //handle defaults
    encrypt = (typeof encrypt !== 'undefined' ? encrypt : true);
    isRetry = (typeof isRetry !== 'undefined' ? isRetry : false);

    var promise = null;
    if (encrypt) {
	  promise = self.cryptoClient.encryptWeaveBasicObject(wbo, collection);
    } else {
      promise = P(wbo);
    }
    
    return promise
      .then(function(wbo) {
        return self.storageClient.put(collection, id, wbo)
      })
      .fail(function(error) {
        if ( !isRetry && error.match(/401\s+unauthorized/i) ) {
          weave.util.Log.warn("Request unauthorized - requesting new sync token");
          return self.initStorageAndCrypto()
            .then(function() {
              return self.put(collection, id, wbo, encrypt, true)
            });
        } else {
          weave.util.Log.error("Couldn't put weave item - " + error);
          return P.reject(error);
        }
      });
  },

  delete: function(collection, id, isRetry) {
    weave.util.Log.debug("WeaveClient.delete()");    

    var self = this;
    
    //handle defaults
    isRetry = (typeof isRetry !== 'undefined' ? isRetry : false);

    return this.storageClient.delete(collection, id)
      .fail(function(error) {
        if ( !isRetry && error.match(/401\s+unauthorized/i) ) {
          weave.util.Log.warn("Request unauthorized - requesting new sync token");
          return self.initStorageAndCrypto()
            .then(function() {
              return self.delete(collection, id, true)
            });
        } else {
          weave.util.Log.error("Couldn't put weave item - " + error);
          return P.reject(error);
        }
      });
  },

  deleteCollection: function(collection) {
    weave.util.Log.debug("WeaveClient.deleteCollection()");
    throw new weave.error.WeaveError("Delete not yet implemented");
  },

  getCollectionInfo: function(collection, getcount, getusage, isRetry) {
    weave.util.Log.debug("WeaveClient.getCollectionInfo()");

    var self = this;

    //handle defaults
    getcount = (typeof getcount !== 'undefined' ? getcount : false);
    getusage = (typeof getusage !== 'undefined' ? getusage : false);
    isRetry  = (typeof isRetry !== 'undefined' ? isRetry : false);

	return this.storageClient.getInfoCollections(getcount, getusage)
      .then(function(colinfo) {
        if (colinfo && colinfo[collection]) {
          return P(colinfo[collection]);
        } else {
          return P.reject(sprintf("No info for collection '%s'", collection));
        }
      })
      .fail(function(error) {
        if ( !isRetry && error.match(/401\s+unauthorized/i) ) {
          weave.util.Log.warn("Request unauthorized - requesting new sync token");
          return self.initStorageAndCrypto()
            .then(function() {
              return self.getCollectionInfo(collection, getcount, getusage, true)
            });
        } else {
          weave.util.Log.error("Couldn't get weave collection info - " + error);
          return P.reject(error);
        }
      });
  },

  decryptWeaveBasicObject: function(wbo, collection) {
    weave.util.Log.debug("WeaveClient.decryptWeaveBasicObject()");
	return this.cryptoClient.decryptWeaveBasicObject(wbo, collection);
  },

  encryptWeaveBasicObject: function(wbo, collection) {
    weave.util.Log.debug("WeaveClient.encryptWeaveBasicObject()");
	return this.cryptoClient.encryptWeaveBasicObject(wbo, collection);
  }


};

module.exports = baseClient;


},{"./weave-crypto":4,"./weave-error":5,"./weave-storage":7,"./weave-util":8,"p-promise":16,"sprintf":18}],4:[function(require,module,exports){
(function (global){
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
var forge   = (typeof window !== "undefined" ? window['forge'] : typeof global !== "undefined" ? global['forge'] : null);
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

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./weave-error":5,"./weave-storage":7,"./weave-util":8,"p-promise":16,"sprintf":18}],5:[function(require,module,exports){
/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave helper objects
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

var error = {};

error.WeaveError = function(e) {
  if ( e instanceof Error ) {
    this.message = e.message;
  } else {
    this.message = e;
  }
}

error.WeaveError.prototype = new Error();
error.WeaveError.prototype.constructor = error.WeaveError;

module.exports = error;

},{}],6:[function(require,module,exports){
//nodejs includes
//var util = require('util');

//npm includes
var sprintf = require('sprintf');
var hawk = require('hawk');
var P = require('p-promise');

var weave = {};
weave.error = require('./weave-error');
weave.util  = require('./weave-util');

weave.net = {};

weave.net.HttpClient = function(xhr, options) {
  if ( !xhr ) {
    if ( typeof XMLHttpRequest !== 'undefined' ) {
      xhr = XMLHttpRequest;
    } else {
      xhr = require("xmlhttprequest").XMLHttpRequest;
    }
  }
    
  if (!options) {
    options = {};
  }
  
  this.xhr = xhr;
  this.timeout = options.timeout || 30 * 1000;
  
  this.authProvider = null;
};
weave.net.HttpClient.prototype = {

  'DEFAULT_TIMEOUT': 5000,
  
  setAuthProvider: function(provider) {
    this.authProvider = provider;
  },
  
  get: function(url, timeout, headers) {
    weave.util.Log.debug("HttpClient.get()");

    var xhr = new this.xhr();
      
    xhr.open('GET', url, false);  // synchronous request
    xhr.timeout = timeout;
    
    if ( this.authProvider !== null ) {
      this.authProvider.setAuthHeader(xhr, url, 'GET');
    }

    if ( headers !== undefined ) {
      for (var key in headers) {
        xhr.setRequestHeader(key, headers[key]);
      }
    }

    xhr.send(null);
    
    if (xhr.status != 200) {
      throw new weave.error.WeaveError("Http request failed - " + xhr.status + " - " + xhr.statusText);
    }

	return xhr.responseText;
  },    

  asyncRequest: function(method, url, timeout, headers, data) {
    weave.util.Log.debug("HttpClient.asyncRequest()");

    //defaults
    timeout = (typeof timeout !== 'undefined' ? timeout : this.DEFAULT_TIMEOUT);
    headers = (typeof headers !== 'undefined' ? headers : {});
    data = (typeof data !== 'undefined' ? data : null);
    
    var xhr = new this.xhr();

    var deferred = P.defer();

    xhr.ontimeout = function () {
      deferred.reject("Http " + method + " request for " + url + " timed out.");
    };
      
    xhr.onload = function() {
      if (xhr.readyState !== 4) {
        return;
      }
      
      if (xhr.status !== 200) {
        weave.util.Log.debug("Http " + method + " request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
        deferred.reject(xhr.status + " " + xhr.statusText);
      }

      deferred.resolve(xhr.responseText);
    };
    
    xhr.open(method, url, true);
    xhr.timeout = timeout;
    
    if ( this.authProvider !== null ) {
      this.authProvider.setAuthHeader(xhr, url, method);
    }

    for (var key in headers) {
      xhr.setRequestHeader(key, headers[key]);
    }

    xhr.send(data);

    return deferred.promise;
  },

  asyncGet: function(url, timeout, headers) {
    weave.util.Log.debug("HttpClient.asyncGet()");

    return this.asyncRequest('GET', url, timeout, headers);
    
    /*
    var xhr = new this.xhr();

    var deferred = P.defer();
    
    xhr.ontimeout = function () {
      //throw new weave.error.WeaveError("Http request for " + url + " timed out.");
      deferred.reject("Http request for " + url + " timed out.");
    };
      
    xhr.onload = function() {
      if (xhr.readyState !== 4) {
        return;
      }
      
      if (xhr.status !== 200) {
        //throw new weave.error.WeaveError("Http request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
        deferred.reject("Http request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
      }

      deferred.resolve(xhr.responseText);
    };
    
    xhr.open("GET", url, true);
    xhr.timeout = timeout;
    
    if ( this.authProvider !== null ) {
      this.authProvider.setAuthHeader(xhr, url, 'GET');
    }

    if ( headers !== undefined ) {
      for (var key in headers) {
        xhr.setRequestHeader(key, headers[key]);
      }
    }

    xhr.send(null);

    return deferred.promise;
    */
  },

  asyncPut: function(url, timeout, headers, data) {
    weave.util.Log.debug("HttpClient.asyncPut()");

    return this.asyncRequest('PUT', url, timeout, headers, data);
    
    /*
    var xhr = new this.xhr();

    var deferred = P.defer();
    
    xhr.ontimeout = function () {
      //throw new weave.error.WeaveError("Http request for " + url + " timed out.");
      deferred.reject("Http request for " + url + " timed out.");
    };
      
    xhr.onload = function() {
      if (xhr.readyState !== 4) {
        return;
      }
      
      if (xhr.status !== 200) {
        //throw new weave.error.WeaveError("Http request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
        deferred.reject("Http request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
      }

      deferred.resolve(xhr.responseText);
    };
    
    xhr.open("PUT", url, true);
    xhr.timeout = timeout;
    
    if ( this.authProvider !== null ) {
      this.authProvider.setAuthHeader(xhr, url, 'PUT');
    }

    if ( headers !== undefined ) {
      for (var key in headers) {
        xhr.setRequestHeader(key, headers[key]);
      }
    }

    xhr.send(data);

    return deferred.promise;
    */
  },

  asyncDelete: function(url, timeout, headers) {
    weave.util.Log.debug("HttpClient.asyncDelete()");

    return this.asyncRequest('DELETE', url, timeout, headers);
  }

};

weave.net.BasicAuthProvider = function(auth) {
  this.username = null;
  this.password = null;
  this.init(auth)
}

weave.net.BasicAuthProvider.prototype = {
  init: function(auth) {
    this.username = auth.username;
    this.password = auth.password;
  },
  
  setAuthHeader: function(xhr) {
    var header = "Basic " + weave.util.Base64.encode(this.username + ":" + this.password);
    xhr.setRequestHeader("Authorization", header);
  }
};

weave.net.BrowserIdAuthProvider = function(auth) {
  this.assertion = null;
  this.init(auth)
}

weave.net.BrowserIdAuthProvider.prototype = {
  init: function(auth) {
    this.assertion  = auth.assertion;
  },
  
  setAuthHeader: function(xhr) {
    var header = "BrowserID " + this.assertion;
    xhr.setRequestHeader("Authorization", header);
  }
};

weave.net.HawkAuthProvider = function(auth) {
  this.hawkid  = null;
  this.hawkkey = null;
  this.init(auth)
}

weave.net.HawkAuthProvider.prototype = {
  init: function(auth) {
    this.hawkid  = auth.hawkid;
    this.hawkkey = auth.hawkkey;
  },
  
  setAuthHeader: function(xhr, url, method) {
	var creds = {
	  'id': this.hawkid,
	  'key': this.hawkkey,
	  'algorithm': "sha256"
	};

	var hawkHeader = hawk.client.header(url, method, {"credentials": creds, "ext": ""});
    xhr.setRequestHeader("Authorization", hawkHeader.field);
  }
};

weave.net.Http = (function() {
  var httpClient = new weave.net.HttpClient();
  return {
    setCredentials: function(auth) {
      return httpClient.setAuthProvider(new weave.net.BasicAuthProvider(auth));
    },
    get: function(url, timeout) {
      weave.util.Log.debug("weave.net.Http.get()");
      return httpClient.get(url, timeout);
    }
  };
}());

module.exports = weave.net;

},{"./weave-error":5,"./weave-util":8,"hawk":14,"p-promise":16,"sprintf":18,"xmlhttprequest":undefined}],7:[function(require,module,exports){
(function (global){
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
var forge   = (typeof window !== "undefined" ? window['forge'] : typeof global !== "undefined" ? global['forge'] : null);
var P       = require('p-promise');

//app includes
var weave = {};
weave.error  = require('./weave-error');
weave.net    = require('./weave-net');
weave.util   = require('./weave-util');

var storage = {};

storage.WeaveBasicObject = function() {  
  this.id        = null;
  this.modified  = null;
  this.sortindex = null;
  this.ttl       = null;
  this.payload   = null;
}

storage.WeaveBasicObject.prototype = {
  getPayloadAsJSONObject: function() {
    weave.util.Log.debug("WeaveBasicObject.getPayloadAsJSONObject()");
    return JSON.parse(this.payload);
  },

  fromJSONObject: function(jsonObject) {
    this.id        = jsonObject.id;
    this.modified  = jsonObject.modified;
    this.sortindex = jsonObject.sortindex;
    this.ttl       = jsonObject.ttl;
    this.payload   = jsonObject.payload;
  },

  toJSONObject: function() {
    return {
      id:        this.id,
      modified:  this.modified,
      sortindex: this.sortindex,
      ttl:       this.ttl,
      payload:   this.payload
    };
  }
};

storage.StorageClientFactory = (function() {
  return {
    getInstance: function(params) {
      var storageClient = new storage["StorageClient" + params.apiVersion.toUpperCase()]();
      storageClient.init(params);
      return storageClient;
    }    
  };
})();

storage.StorageClient = function() {
  this.storageURL = null;
  this.httpClient = new weave.net.HttpClient();
};

storage.StorageClient.prototype = {

  get: function(collection, id) {
	weave.util.Log.debug("StorageClient.get()");

    var path = null;
    if (typeof id !== 'undefined') {
      //build path from collection and id
      path = collection + "/" + id;
    } else {
      //assume first arg is path
      path = collection;
    }

    var url = this.buildStorageUri(path);
    
    return this.httpClient.asyncGet(url)
      .then(function(response) {
        var jsonObject = JSON.parse(response);
        var wbo        = new storage.WeaveBasicObject();
        wbo.fromJSONObject(jsonObject);
        return P(wbo);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get weave item - " + error);
        return P.reject(error);
      });
  },

  buildStorageUri: function(path, root) {
    root = (typeof root !== 'undefined' ? root : false);
    if (root) {
      return URI(path).absoluteTo(this.storageURL).toString();
    } else {
      return URI("storage/" + path).absoluteTo(this.storageURL).toString();
    }
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
		throw new weave.error.WeaveError(sprintf("buildCollectionUri() sort parameter value of '%s' not recognised", sort));
	  }
	}
	if (format !== null) {
	  //Only default format supported
	  throw new weave.error.WeaveError(sprintf("buildCollectionUri() format parameter value of '%s' not supported", format));
	}
	if ( full ) {
	  //returns entire WBO
	  params['full'] = "1";
	}

	return URI(this.buildStorageUri(collection)).query(params).toString();
  },
  
  getCollectionIds: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort) {
    weave.util.Log.debug("StorageClient.getCollectionIds()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, null, false);

    return this.httpClient.asyncGet(url)
      .then(function(response) {
        var ids = JSON.parse(response);
        return P(ids);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get weave collection ids - " + error);
        return P.reject(error);
      });
  },
  
  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format) {
    weave.util.Log.debug("StorageClient.getCollection()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, true);

    return this.httpClient.asyncGet(url)
      .then(function(response) {
        var jsonArray = JSON.parse(response);
        
        var wbos = [];
        for (var i = 0; i < jsonArray.length; i++) {
          var jsonObject = jsonArray[i];
          var wbo        = new storage.WeaveBasicObject();
          wbo.fromJSONObject(jsonObject);
            wbos.push(wbo);
        }
        return P(wbos);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get weave collection - " + error);
        return P.reject(error);
      });
  },

  put: function(collection, id, wbo) {
	weave.util.Log.debug("StorageClient.put()");

    var self = this;
    
    var path = collection + "/" + id;
    var url = this.buildStorageUri(path);
    var data = JSON.stringify(wbo.toJSONObject());
        
    return this.httpClient.asyncPut(url, undefined, undefined, data)
      .then(function(response) {
        //First try to parse response as JSON otherwise treat as raw modified value
        var modified = null;
        var jsonObject = JSON.parse(response);
        if (typeof jsonObject === 'object' && jsonObject.modified) {
          modified = jsonObject.modified;
        } else {
          modified = parseFloat(response);
        }
        return P(modified);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't put weave item - " + error);
        return P.reject(error);
      });
  },

  delete: function(collection, id) {
	weave.util.Log.debug("StorageClient.delete()");

    var self = this;
    
    var path = collection + "/" + id;
    var url = this.buildStorageUri(path);
        
    return this.httpClient.asyncDelete(url)
      .then(function(response) {
        //First try to parse response as JSON otherwise treat as raw modified value
        var modified = null;
        var jsonObject = JSON.parse(response);
        if (typeof jsonObject === 'object' && jsonObject.modified) {
          modified = jsonObject.modified;
        } else {
          modified = parseFloat(response);
        }
        return P(modified);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't delete weave item - " + error);
        return P.reject(error);
      });
  },

  getInfoCollections: function(getcount, getusage) {
	weave.util.Log.debug("StorageClient.getInfoCollections()");

    var self = this;
    
    var url = this.buildStorageUri("info/collections", true);
    return this.httpClient.asyncGet(url)
      .then(function(response) {
        var colModified = JSON.parse(response);
        var cols = {};
        for (var col in colModified) {
          if (!cols[col]) {
            cols[col] = {};
          }
          cols[col].modified = colModified[col];
        }
        return P(cols);
      })
      .then(function(cols) {
		//Optionally get info/collection_counts
		if ( getcount ) {
          var url = self.buildStorageUri("info/collection_counts", true);
          return self.httpClient.asyncGet(url)
            .then(function(response) {
	          var colCounts = JSON.parse(response);
              for (var col in colCounts) {
                if (!cols[col]) {
                  cols[col] = {};
                }
                cols[col].count = colCounts[col];
              }
              return P(cols);
			})
		} else {
          return P(cols);
        }
	  })
      .then(function(cols) {
		//Optionally get info/collection_usage
		if ( getusage ) {
          var url = self.buildStorageUri("info/collection_usage", true);
          return self.httpClient.asyncGet(url)
            .then(function(response) {
	          var colUsage = JSON.parse(response);
              for (var col in colUsage) {
                if (!cols[col]) {
                  cols[col] = {};
                }
                cols[col].usage = colUsage[col];
              }
              return P(cols);
			})
		} else {
          return P(cols);
        }		
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get weave item - " + error);
        return P.reject(error);
      });
  }

};

storage.StorageClientV1_1 = function() {
  storage.StorageClient.call(this);
  this.user     = null;
  this.password = null;
}

storage.StorageClientV1_1.prototype = Object.create(storage.StorageClient.prototype);
storage.StorageClientV1_1.prototype.constructor = storage.StorageClientV1_1;

storage.StorageClientV1_1.prototype.init = function(params) {
  weave.util.Log.debug("StorageClientV1_1.init()");

  this.storageURL = URI(sprintf("1.1/%s/", params.user)).absoluteTo(params.storageURL).toString();
  this.user       = params.user;
  this.password   = params.password;
  
  this.httpClient.setAuthProvider(new weave.net.BasicAuthProvider({username: this.user, password: this.password}));
}

storage.StorageClientV1_5 = function() {
  storage.StorageClient.call(this);
  this.hawkid  = null;
  this.hawkkey = null;
}

storage.StorageClientV1_5.prototype = Object.create(storage.StorageClient.prototype);
storage.StorageClientV1_5.prototype.constructor = storage.StorageClientV1_5;

storage.StorageClientV1_5.prototype.init = function(params) {
  weave.util.Log.debug("StorageClientV1_5.init()");
  this.storageURL = params.storageURL.match('\/$/') ? params.storageURL : params.storageURL + '/';
  this.hawkid     = params.hawkid;
  this.hawkkey    = params.hawkkey;

  this.httpClient.setAuthProvider(new weave.net.HawkAuthProvider({hawkid: this.hawkid, hawkkey: this.hawkkey}));
}

module.exports = storage;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./weave-error":5,"./weave-net":6,"./weave-util":8,"URIjs":11,"p-promise":16,"sprintf":18,"util":20}],8:[function(require,module,exports){
(function (global){
//npm includes
var forge   = (typeof window !== "undefined" ? window['forge'] : typeof global !== "undefined" ? global['forge'] : null);

//app includes
var weave = {};
weave.error = require('./weave-error');

weave.util = {};

weave.util.Log = (function() {

  var logLevel = {
    debug: "debug",
    info:  "info",
    warn:  "warning",
    error: "error"
  };

  var logMessage = function(level, msg) {
    //console.log("weave.util.Log.log(), level: " + logLevel[level]);
    forge.log.logMessage({timestamp: new Date(), level: logLevel[level], category: "weaveclient-js", message: msg});
  };

  return {
    setLevel: function(level) {
      //console.log("weave.util.Log.setLevel(), level: " + logLevel[level]);
      forge.log.setLevel(forge.log.consoleLogger, logLevel[level]);
    },
    log:   function(level, msg) {logMessage(level, msg); },
    debug: function(msg) { logMessage("debug", msg); },
    info:  function(msg) { logMessage("info", msg); },
    warn:  function(msg) { logMessage("warn", msg); },
    error: function(msg) { logMessage("error", msg); }
  };
})();

weave.util.Base64 = (function() {
  
  return {
    decode: function(encoded) { 
      return forge.util.decode64(encoded)
    },

    encode: function(bin) {
      return forge.util.encode64(bin)
    }

  };
 
})();

weave.util.Base32 = (function() {

  return {
    decode: function(encoded) { 

      /// <summary>Decodes a base32 encoded string into a Uin8Array, note padding is not supported</summary>
      /// <param name="encoded" type="String">The base32 encoded string to be decoded</param>
      /// <returns type="Uint8Array">The Unit8Array representation of the data that was encoded in encoded</returns>
      if (!encoded && encoded !== "") {
        throw "encoded cannot be null or undefined";
      }

      if (encoded.length * 5 % 8 !== 0) {
        throw "encoded is not of the proper length. Please verify padding.";
      }

      encoded = encoded.toLowerCase();
      var alphabet = "abcdefghijklmnopqrstuvwxyz234567";
      var returnArray = new Array(encoded.length * 5 / 8);

      var currentByte = 0;
      var bitsRemaining = 8;
      var mask = 0;
      var arrayIndex = 0;

      for (var count = 0; count < encoded.length; count++) {
        var currentIndexValue = alphabet.indexOf(encoded[count]);
        if (-1 === currentIndexValue) {
          if ("=" === encoded[count]) {
            var paddingCount = 0;
            for (count = count; count < encoded.length; count++) {
              if ("=" !== encoded[count]) {
                throw "Invalid '=' in encoded string";
              } else {
                paddingCount++;
              }
            }

            switch (paddingCount) {
            case 6:
              returnArray = returnArray.slice(0, returnArray.length - 4);
              break;
            case 4:
              returnArray = returnArray.slice(0, returnArray.length - 3);
              break;
            case 3:
              returnArray = returnArray.slice(0, returnArray.length - 2);
              break;
            case 1:
              returnArray = returnArray.slice(0, returnArray.length - 1);
              break;
            default:
              throw "Incorrect padding";
            }
          } else {
            throw "Encoded string contains invalid characters or invalid padding.";
          }
        } else {
          if (bitsRemaining > 5) {
            mask = currentIndexValue << (bitsRemaining - 5);
            currentByte = currentByte | mask;
            bitsRemaining -= 5;
          } else {
            mask = currentIndexValue >> (5 - bitsRemaining);
            currentByte = currentByte | mask;
            returnArray[arrayIndex++] = currentByte;
            currentByte = currentIndexValue << (3 + bitsRemaining);
            bitsRemaining += 3;
          }
        }
      }

      var retval = new Uint8Array(returnArray);
      return weave.util.BinUtils.uint8ToString(retval);
    },

    encode: function(bin) {
      throw new weave.WeaveError("Base 32 encode not supported");
    }

  };

})();

weave.util.Hex = (function() {
  
  return {
    decode: function(encoded) { 
      return forge.util.hexToBytes(encoded)
    },

    encode: function(bin) {
      return forge.util.bytesToHex(bin)
    }

  };
 
})();

weave.util.BinUtils = (function() {

  return {
    uint8ToString: function(u8a){
      var CHUNK_SZ = 0x8000;
      var c = [];
      for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
      }
      return c.join("");
    },

    binConcat: function() {
      var buf = forge.util.createBuffer();
      for (var i = 0; i < arguments.length; i++) {
        var tmpBuf = forge.util.createBuffer(arguments[i], 'raw');
        buf.putBytes(tmpBuf.getBytes());
      }
      return buf.getBytes();
    }
  }
  
})();

weave.util.UTF8 = (function() {
  return {
    decode: function(encoded) {
      return forge.util.decodeUtf8(encoded);
    },

    encode: function(string) {
      return forge.util.encodeUtf8(string);
    }

  };

})();

weave.util.StringUtils = (function () {

  return {
    STR_PAD_LEFT: 1,
    STR_PAD_RIGHT: 2,
    STR_PAD_BOTH: 3,

    /**
     *
     *  Javascript string pad
     *  http://www.webtoolkit.info/
     *
     **/
    pad: function(str, len, pad, dir) {

      if (typeof(len) == "undefined") { var len = 0; }
      if (typeof(pad) == "undefined") { var pad = ' '; }
      if (typeof(dir) == "undefined") { var dir = STR_PAD_RIGHT; }

      if (len + 1 >= str.length) {

        switch (dir){

        case this.STR_PAD_LEFT:
          str = Array(len + 1 - str.length).join(pad) + str;
          break;

        case this.STR_PAD_BOTH:
          var right = Math.ceil((padlen = len - str.length) / 2);
          var left = padlen - right;
          str = Array(left+1).join(pad) + str + Array(right+1).join(pad);
          break;

        default:
          str = str + Array(len + 1 - str.length).join(pad);
          break;

        } // switch

      }

      return str;      
    },

    leftPad: function(str, len, pad) {
      return this.pad(str, len, pad, this.STR_PAD_LEFT);
    },

    rightPad: function(str, len, pad) {
      return this.pad(str, len, pad, this.STR_PAD_RIGHT);
    }

  };

})();

module.exports = weave.util;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./weave-error":5}],9:[function(require,module,exports){
/*!
 * URI.js - Mutating URLs
 * IPv6 Support
 *
 * Version: 1.16.1
 *
 * Author: Rodney Rehm
 * Web: http://medialize.github.io/URI.js/
 *
 * Licensed under
 *   MIT License http://www.opensource.org/licenses/mit-license
 *   GPL v3 http://opensource.org/licenses/GPL-3.0
 *
 */

(function (root, factory) {
  'use strict';
  // https://github.com/umdjs/umd/blob/master/returnExports.js
  if (typeof exports === 'object') {
    // Node
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(factory);
  } else {
    // Browser globals (root is window)
    root.IPv6 = factory(root);
  }
}(this, function (root) {
  'use strict';

  /*
  var _in = "fe80:0000:0000:0000:0204:61ff:fe9d:f156";
  var _out = IPv6.best(_in);
  var _expected = "fe80::204:61ff:fe9d:f156";

  console.log(_in, _out, _expected, _out === _expected);
  */

  // save current IPv6 variable, if any
  var _IPv6 = root && root.IPv6;

  function bestPresentation(address) {
    // based on:
    // Javascript to test an IPv6 address for proper format, and to
    // present the "best text representation" according to IETF Draft RFC at
    // http://tools.ietf.org/html/draft-ietf-6man-text-addr-representation-04
    // 8 Feb 2010 Rich Brown, Dartware, LLC
    // Please feel free to use this code as long as you provide a link to
    // http://www.intermapper.com
    // http://intermapper.com/support/tools/IPV6-Validator.aspx
    // http://download.dartware.com/thirdparty/ipv6validator.js

    var _address = address.toLowerCase();
    var segments = _address.split(':');
    var length = segments.length;
    var total = 8;

    // trim colons (:: or ::a:b:c… or …a:b:c::)
    if (segments[0] === '' && segments[1] === '' && segments[2] === '') {
      // must have been ::
      // remove first two items
      segments.shift();
      segments.shift();
    } else if (segments[0] === '' && segments[1] === '') {
      // must have been ::xxxx
      // remove the first item
      segments.shift();
    } else if (segments[length - 1] === '' && segments[length - 2] === '') {
      // must have been xxxx::
      segments.pop();
    }

    length = segments.length;

    // adjust total segments for IPv4 trailer
    if (segments[length - 1].indexOf('.') !== -1) {
      // found a "." which means IPv4
      total = 7;
    }

    // fill empty segments them with "0000"
    var pos;
    for (pos = 0; pos < length; pos++) {
      if (segments[pos] === '') {
        break;
      }
    }

    if (pos < total) {
      segments.splice(pos, 1, '0000');
      while (segments.length < total) {
        segments.splice(pos, 0, '0000');
      }

      length = segments.length;
    }

    // strip leading zeros
    var _segments;
    for (var i = 0; i < total; i++) {
      _segments = segments[i].split('');
      for (var j = 0; j < 3 ; j++) {
        if (_segments[0] === '0' && _segments.length > 1) {
          _segments.splice(0,1);
        } else {
          break;
        }
      }

      segments[i] = _segments.join('');
    }

    // find longest sequence of zeroes and coalesce them into one segment
    var best = -1;
    var _best = 0;
    var _current = 0;
    var current = -1;
    var inzeroes = false;
    // i; already declared

    for (i = 0; i < total; i++) {
      if (inzeroes) {
        if (segments[i] === '0') {
          _current += 1;
        } else {
          inzeroes = false;
          if (_current > _best) {
            best = current;
            _best = _current;
          }
        }
      } else {
        if (segments[i] === '0') {
          inzeroes = true;
          current = i;
          _current = 1;
        }
      }
    }

    if (_current > _best) {
      best = current;
      _best = _current;
    }

    if (_best > 1) {
      segments.splice(best, _best, '');
    }

    length = segments.length;

    // assemble remaining segments
    var result = '';
    if (segments[0] === '')  {
      result = ':';
    }

    for (i = 0; i < length; i++) {
      result += segments[i];
      if (i === length - 1) {
        break;
      }

      result += ':';
    }

    if (segments[length - 1] === '') {
      result += ':';
    }

    return result;
  }

  function noConflict() {
    /*jshint validthis: true */
    if (root.IPv6 === this) {
      root.IPv6 = _IPv6;
    }
  
    return this;
  }

  return {
    best: bestPresentation,
    noConflict: noConflict
  };
}));

},{}],10:[function(require,module,exports){
/*!
 * URI.js - Mutating URLs
 * Second Level Domain (SLD) Support
 *
 * Version: 1.16.1
 *
 * Author: Rodney Rehm
 * Web: http://medialize.github.io/URI.js/
 *
 * Licensed under
 *   MIT License http://www.opensource.org/licenses/mit-license
 *   GPL v3 http://opensource.org/licenses/GPL-3.0
 *
 */

(function (root, factory) {
  'use strict';
  // https://github.com/umdjs/umd/blob/master/returnExports.js
  if (typeof exports === 'object') {
    // Node
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(factory);
  } else {
    // Browser globals (root is window)
    root.SecondLevelDomains = factory(root);
  }
}(this, function (root) {
  'use strict';

  // save current SecondLevelDomains variable, if any
  var _SecondLevelDomains = root && root.SecondLevelDomains;

  var SLD = {
    // list of known Second Level Domains
    // converted list of SLDs from https://github.com/gavingmiller/second-level-domains
    // ----
    // publicsuffix.org is more current and actually used by a couple of browsers internally.
    // downside is it also contains domains like "dyndns.org" - which is fine for the security
    // issues browser have to deal with (SOP for cookies, etc) - but is way overboard for URI.js
    // ----
    list: {
      'ac':' com gov mil net org ',
      'ae':' ac co gov mil name net org pro sch ',
      'af':' com edu gov net org ',
      'al':' com edu gov mil net org ',
      'ao':' co ed gv it og pb ',
      'ar':' com edu gob gov int mil net org tur ',
      'at':' ac co gv or ',
      'au':' asn com csiro edu gov id net org ',
      'ba':' co com edu gov mil net org rs unbi unmo unsa untz unze ',
      'bb':' biz co com edu gov info net org store tv ',
      'bh':' biz cc com edu gov info net org ',
      'bn':' com edu gov net org ',
      'bo':' com edu gob gov int mil net org tv ',
      'br':' adm adv agr am arq art ato b bio blog bmd cim cng cnt com coop ecn edu eng esp etc eti far flog fm fnd fot fst g12 ggf gov imb ind inf jor jus lel mat med mil mus net nom not ntr odo org ppg pro psc psi qsl rec slg srv tmp trd tur tv vet vlog wiki zlg ',
      'bs':' com edu gov net org ',
      'bz':' du et om ov rg ',
      'ca':' ab bc mb nb nf nl ns nt nu on pe qc sk yk ',
      'ck':' biz co edu gen gov info net org ',
      'cn':' ac ah bj com cq edu fj gd gov gs gx gz ha hb he hi hl hn jl js jx ln mil net nm nx org qh sc sd sh sn sx tj tw xj xz yn zj ',
      'co':' com edu gov mil net nom org ',
      'cr':' ac c co ed fi go or sa ',
      'cy':' ac biz com ekloges gov ltd name net org parliament press pro tm ',
      'do':' art com edu gob gov mil net org sld web ',
      'dz':' art asso com edu gov net org pol ',
      'ec':' com edu fin gov info med mil net org pro ',
      'eg':' com edu eun gov mil name net org sci ',
      'er':' com edu gov ind mil net org rochest w ',
      'es':' com edu gob nom org ',
      'et':' biz com edu gov info name net org ',
      'fj':' ac biz com info mil name net org pro ',
      'fk':' ac co gov net nom org ',
      'fr':' asso com f gouv nom prd presse tm ',
      'gg':' co net org ',
      'gh':' com edu gov mil org ',
      'gn':' ac com gov net org ',
      'gr':' com edu gov mil net org ',
      'gt':' com edu gob ind mil net org ',
      'gu':' com edu gov net org ',
      'hk':' com edu gov idv net org ',
      'hu':' 2000 agrar bolt casino city co erotica erotika film forum games hotel info ingatlan jogasz konyvelo lakas media news org priv reklam sex shop sport suli szex tm tozsde utazas video ',
      'id':' ac co go mil net or sch web ',
      'il':' ac co gov idf k12 muni net org ',
      'in':' ac co edu ernet firm gen gov i ind mil net nic org res ',
      'iq':' com edu gov i mil net org ',
      'ir':' ac co dnssec gov i id net org sch ',
      'it':' edu gov ',
      'je':' co net org ',
      'jo':' com edu gov mil name net org sch ',
      'jp':' ac ad co ed go gr lg ne or ',
      'ke':' ac co go info me mobi ne or sc ',
      'kh':' com edu gov mil net org per ',
      'ki':' biz com de edu gov info mob net org tel ',
      'km':' asso com coop edu gouv k medecin mil nom notaires pharmaciens presse tm veterinaire ',
      'kn':' edu gov net org ',
      'kr':' ac busan chungbuk chungnam co daegu daejeon es gangwon go gwangju gyeongbuk gyeonggi gyeongnam hs incheon jeju jeonbuk jeonnam k kg mil ms ne or pe re sc seoul ulsan ',
      'kw':' com edu gov net org ',
      'ky':' com edu gov net org ',
      'kz':' com edu gov mil net org ',
      'lb':' com edu gov net org ',
      'lk':' assn com edu gov grp hotel int ltd net ngo org sch soc web ',
      'lr':' com edu gov net org ',
      'lv':' asn com conf edu gov id mil net org ',
      'ly':' com edu gov id med net org plc sch ',
      'ma':' ac co gov m net org press ',
      'mc':' asso tm ',
      'me':' ac co edu gov its net org priv ',
      'mg':' com edu gov mil nom org prd tm ',
      'mk':' com edu gov inf name net org pro ',
      'ml':' com edu gov net org presse ',
      'mn':' edu gov org ',
      'mo':' com edu gov net org ',
      'mt':' com edu gov net org ',
      'mv':' aero biz com coop edu gov info int mil museum name net org pro ',
      'mw':' ac co com coop edu gov int museum net org ',
      'mx':' com edu gob net org ',
      'my':' com edu gov mil name net org sch ',
      'nf':' arts com firm info net other per rec store web ',
      'ng':' biz com edu gov mil mobi name net org sch ',
      'ni':' ac co com edu gob mil net nom org ',
      'np':' com edu gov mil net org ',
      'nr':' biz com edu gov info net org ',
      'om':' ac biz co com edu gov med mil museum net org pro sch ',
      'pe':' com edu gob mil net nom org sld ',
      'ph':' com edu gov i mil net ngo org ',
      'pk':' biz com edu fam gob gok gon gop gos gov net org web ',
      'pl':' art bialystok biz com edu gda gdansk gorzow gov info katowice krakow lodz lublin mil net ngo olsztyn org poznan pwr radom slupsk szczecin torun warszawa waw wroc wroclaw zgora ',
      'pr':' ac biz com edu est gov info isla name net org pro prof ',
      'ps':' com edu gov net org plo sec ',
      'pw':' belau co ed go ne or ',
      'ro':' arts com firm info nom nt org rec store tm www ',
      'rs':' ac co edu gov in org ',
      'sb':' com edu gov net org ',
      'sc':' com edu gov net org ',
      'sh':' co com edu gov net nom org ',
      'sl':' com edu gov net org ',
      'st':' co com consulado edu embaixada gov mil net org principe saotome store ',
      'sv':' com edu gob org red ',
      'sz':' ac co org ',
      'tr':' av bbs bel biz com dr edu gen gov info k12 name net org pol tel tsk tv web ',
      'tt':' aero biz cat co com coop edu gov info int jobs mil mobi museum name net org pro tel travel ',
      'tw':' club com ebiz edu game gov idv mil net org ',
      'mu':' ac co com gov net or org ',
      'mz':' ac co edu gov org ',
      'na':' co com ',
      'nz':' ac co cri geek gen govt health iwi maori mil net org parliament school ',
      'pa':' abo ac com edu gob ing med net nom org sld ',
      'pt':' com edu gov int net nome org publ ',
      'py':' com edu gov mil net org ',
      'qa':' com edu gov mil net org ',
      're':' asso com nom ',
      'ru':' ac adygeya altai amur arkhangelsk astrakhan bashkiria belgorod bir bryansk buryatia cbg chel chelyabinsk chita chukotka chuvashia com dagestan e-burg edu gov grozny int irkutsk ivanovo izhevsk jar joshkar-ola kalmykia kaluga kamchatka karelia kazan kchr kemerovo khabarovsk khakassia khv kirov koenig komi kostroma kranoyarsk kuban kurgan kursk lipetsk magadan mari mari-el marine mil mordovia mosreg msk murmansk nalchik net nnov nov novosibirsk nsk omsk orenburg org oryol penza perm pp pskov ptz rnd ryazan sakhalin samara saratov simbirsk smolensk spb stavropol stv surgut tambov tatarstan tom tomsk tsaritsyn tsk tula tuva tver tyumen udm udmurtia ulan-ude vladikavkaz vladimir vladivostok volgograd vologda voronezh vrn vyatka yakutia yamal yekaterinburg yuzhno-sakhalinsk ',
      'rw':' ac co com edu gouv gov int mil net ',
      'sa':' com edu gov med net org pub sch ',
      'sd':' com edu gov info med net org tv ',
      'se':' a ac b bd c d e f g h i k l m n o org p parti pp press r s t tm u w x y z ',
      'sg':' com edu gov idn net org per ',
      'sn':' art com edu gouv org perso univ ',
      'sy':' com edu gov mil net news org ',
      'th':' ac co go in mi net or ',
      'tj':' ac biz co com edu go gov info int mil name net nic org test web ',
      'tn':' agrinet com defense edunet ens fin gov ind info intl mincom nat net org perso rnrt rns rnu tourism ',
      'tz':' ac co go ne or ',
      'ua':' biz cherkassy chernigov chernovtsy ck cn co com crimea cv dn dnepropetrovsk donetsk dp edu gov if in ivano-frankivsk kh kharkov kherson khmelnitskiy kiev kirovograd km kr ks kv lg lugansk lutsk lviv me mk net nikolaev od odessa org pl poltava pp rovno rv sebastopol sumy te ternopil uzhgorod vinnica vn zaporizhzhe zhitomir zp zt ',
      'ug':' ac co go ne or org sc ',
      'uk':' ac bl british-library co cym gov govt icnet jet lea ltd me mil mod national-library-scotland nel net nhs nic nls org orgn parliament plc police sch scot soc ',
      'us':' dni fed isa kids nsn ',
      'uy':' com edu gub mil net org ',
      've':' co com edu gob info mil net org web ',
      'vi':' co com k12 net org ',
      'vn':' ac biz com edu gov health info int name net org pro ',
      'ye':' co com gov ltd me net org plc ',
      'yu':' ac co edu gov org ',
      'za':' ac agric alt bourse city co cybernet db edu gov grondar iaccess imt inca landesign law mil net ngo nis nom olivetti org pix school tm web ',
      'zm':' ac co com edu gov net org sch '
    },
    // gorhill 2013-10-25: Using indexOf() instead Regexp(). Significant boost
    // in both performance and memory footprint. No initialization required.
    // http://jsperf.com/uri-js-sld-regex-vs-binary-search/4
    // Following methods use lastIndexOf() rather than array.split() in order
    // to avoid any memory allocations.
    has: function(domain) {
      var tldOffset = domain.lastIndexOf('.');
      if (tldOffset <= 0 || tldOffset >= (domain.length-1)) {
        return false;
      }
      var sldOffset = domain.lastIndexOf('.', tldOffset-1);
      if (sldOffset <= 0 || sldOffset >= (tldOffset-1)) {
        return false;
      }
      var sldList = SLD.list[domain.slice(tldOffset+1)];
      if (!sldList) {
        return false;
      }
      return sldList.indexOf(' ' + domain.slice(sldOffset+1, tldOffset) + ' ') >= 0;
    },
    is: function(domain) {
      var tldOffset = domain.lastIndexOf('.');
      if (tldOffset <= 0 || tldOffset >= (domain.length-1)) {
        return false;
      }
      var sldOffset = domain.lastIndexOf('.', tldOffset-1);
      if (sldOffset >= 0) {
        return false;
      }
      var sldList = SLD.list[domain.slice(tldOffset+1)];
      if (!sldList) {
        return false;
      }
      return sldList.indexOf(' ' + domain.slice(0, tldOffset) + ' ') >= 0;
    },
    get: function(domain) {
      var tldOffset = domain.lastIndexOf('.');
      if (tldOffset <= 0 || tldOffset >= (domain.length-1)) {
        return null;
      }
      var sldOffset = domain.lastIndexOf('.', tldOffset-1);
      if (sldOffset <= 0 || sldOffset >= (tldOffset-1)) {
        return null;
      }
      var sldList = SLD.list[domain.slice(tldOffset+1)];
      if (!sldList) {
        return null;
      }
      if (sldList.indexOf(' ' + domain.slice(sldOffset+1, tldOffset) + ' ') < 0) {
        return null;
      }
      return domain.slice(sldOffset+1);
    },
    noConflict: function(){
      if (root.SecondLevelDomains === this) {
        root.SecondLevelDomains = _SecondLevelDomains;
      }
      return this;
    }
  };

  return SLD;
}));

},{}],11:[function(require,module,exports){
/*!
 * URI.js - Mutating URLs
 *
 * Version: 1.16.1
 *
 * Author: Rodney Rehm
 * Web: http://medialize.github.io/URI.js/
 *
 * Licensed under
 *   MIT License http://www.opensource.org/licenses/mit-license
 *   GPL v3 http://opensource.org/licenses/GPL-3.0
 *
 */
(function (root, factory) {
  'use strict';
  // https://github.com/umdjs/umd/blob/master/returnExports.js
  if (typeof exports === 'object') {
    // Node
    module.exports = factory(require('./punycode'), require('./IPv6'), require('./SecondLevelDomains'));
  } else if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['./punycode', './IPv6', './SecondLevelDomains'], factory);
  } else {
    // Browser globals (root is window)
    root.URI = factory(root.punycode, root.IPv6, root.SecondLevelDomains, root);
  }
}(this, function (punycode, IPv6, SLD, root) {
  'use strict';
  /*global location, escape, unescape */
  // FIXME: v2.0.0 renamce non-camelCase properties to uppercase
  /*jshint camelcase: false */

  // save current URI variable, if any
  var _URI = root && root.URI;

  function URI(url, base) {
    var _urlSupplied = arguments.length >= 1;
    var _baseSupplied = arguments.length >= 2;

    // Allow instantiation without the 'new' keyword
    if (!(this instanceof URI)) {
      if (_urlSupplied) {
        if (_baseSupplied) {
          return new URI(url, base);
        }

        return new URI(url);
      }

      return new URI();
    }

    if (url === undefined) {
      if (_urlSupplied) {
        throw new TypeError('undefined is not a valid argument for URI');
      }

      if (typeof location !== 'undefined') {
        url = location.href + '';
      } else {
        url = '';
      }
    }

    this.href(url);

    // resolve to base according to http://dvcs.w3.org/hg/url/raw-file/tip/Overview.html#constructor
    if (base !== undefined) {
      return this.absoluteTo(base);
    }

    return this;
  }

  URI.version = '1.16.1';

  var p = URI.prototype;
  var hasOwn = Object.prototype.hasOwnProperty;

  function escapeRegEx(string) {
    // https://github.com/medialize/URI.js/commit/85ac21783c11f8ccab06106dba9735a31a86924d#commitcomment-821963
    return string.replace(/([.*+?^=!:${}()|[\]\/\\])/g, '\\$1');
  }

  function getType(value) {
    // IE8 doesn't return [Object Undefined] but [Object Object] for undefined value
    if (value === undefined) {
      return 'Undefined';
    }

    return String(Object.prototype.toString.call(value)).slice(8, -1);
  }

  function isArray(obj) {
    return getType(obj) === 'Array';
  }

  function filterArrayValues(data, value) {
    var lookup = {};
    var i, length;

    if (getType(value) === 'RegExp') {
      lookup = null;
    } else if (isArray(value)) {
      for (i = 0, length = value.length; i < length; i++) {
        lookup[value[i]] = true;
      }
    } else {
      lookup[value] = true;
    }

    for (i = 0, length = data.length; i < length; i++) {
      /*jshint laxbreak: true */
      var _match = lookup && lookup[data[i]] !== undefined
        || !lookup && value.test(data[i]);
      /*jshint laxbreak: false */
      if (_match) {
        data.splice(i, 1);
        length--;
        i--;
      }
    }

    return data;
  }

  function arrayContains(list, value) {
    var i, length;

    // value may be string, number, array, regexp
    if (isArray(value)) {
      // Note: this can be optimized to O(n) (instead of current O(m * n))
      for (i = 0, length = value.length; i < length; i++) {
        if (!arrayContains(list, value[i])) {
          return false;
        }
      }

      return true;
    }

    var _type = getType(value);
    for (i = 0, length = list.length; i < length; i++) {
      if (_type === 'RegExp') {
        if (typeof list[i] === 'string' && list[i].match(value)) {
          return true;
        }
      } else if (list[i] === value) {
        return true;
      }
    }

    return false;
  }

  function arraysEqual(one, two) {
    if (!isArray(one) || !isArray(two)) {
      return false;
    }

    // arrays can't be equal if they have different amount of content
    if (one.length !== two.length) {
      return false;
    }

    one.sort();
    two.sort();

    for (var i = 0, l = one.length; i < l; i++) {
      if (one[i] !== two[i]) {
        return false;
      }
    }

    return true;
  }

  URI._parts = function() {
    return {
      protocol: null,
      username: null,
      password: null,
      hostname: null,
      urn: null,
      port: null,
      path: null,
      query: null,
      fragment: null,
      // state
      duplicateQueryParameters: URI.duplicateQueryParameters,
      escapeQuerySpace: URI.escapeQuerySpace
    };
  };
  // state: allow duplicate query parameters (a=1&a=1)
  URI.duplicateQueryParameters = false;
  // state: replaces + with %20 (space in query strings)
  URI.escapeQuerySpace = true;
  // static properties
  URI.protocol_expression = /^[a-z][a-z0-9.+-]*$/i;
  URI.idn_expression = /[^a-z0-9\.-]/i;
  URI.punycode_expression = /(xn--)/i;
  // well, 333.444.555.666 matches, but it sure ain't no IPv4 - do we care?
  URI.ip4_expression = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  // credits to Rich Brown
  // source: http://forums.intermapper.com/viewtopic.php?p=1096#1096
  // specification: http://www.ietf.org/rfc/rfc4291.txt
  URI.ip6_expression = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
  // expression used is "gruber revised" (@gruber v2) determined to be the
  // best solution in a regex-golf we did a couple of ages ago at
  // * http://mathiasbynens.be/demo/url-regex
  // * http://rodneyrehm.de/t/url-regex.html
  URI.find_uri_expression = /\b((?:[a-z][\w-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))/ig;
  URI.findUri = {
    // valid "scheme://" or "www."
    start: /\b(?:([a-z][a-z0-9.+-]*:\/\/)|www\.)/gi,
    // everything up to the next whitespace
    end: /[\s\r\n]|$/,
    // trim trailing punctuation captured by end RegExp
    trim: /[`!()\[\]{};:'".,<>?«»“”„‘’]+$/
  };
  // http://www.iana.org/assignments/uri-schemes.html
  // http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports
  URI.defaultPorts = {
    http: '80',
    https: '443',
    ftp: '21',
    gopher: '70',
    ws: '80',
    wss: '443'
  };
  // allowed hostname characters according to RFC 3986
  // ALPHA DIGIT "-" "." "_" "~" "!" "$" "&" "'" "(" ")" "*" "+" "," ";" "=" %encoded
  // I've never seen a (non-IDN) hostname other than: ALPHA DIGIT . -
  URI.invalid_hostname_characters = /[^a-zA-Z0-9\.-]/;
  // map DOM Elements to their URI attribute
  URI.domAttributes = {
    'a': 'href',
    'blockquote': 'cite',
    'link': 'href',
    'base': 'href',
    'script': 'src',
    'form': 'action',
    'img': 'src',
    'area': 'href',
    'iframe': 'src',
    'embed': 'src',
    'source': 'src',
    'track': 'src',
    'input': 'src', // but only if type="image"
    'audio': 'src',
    'video': 'src'
  };
  URI.getDomAttribute = function(node) {
    if (!node || !node.nodeName) {
      return undefined;
    }

    var nodeName = node.nodeName.toLowerCase();
    // <input> should only expose src for type="image"
    if (nodeName === 'input' && node.type !== 'image') {
      return undefined;
    }

    return URI.domAttributes[nodeName];
  };

  function escapeForDumbFirefox36(value) {
    // https://github.com/medialize/URI.js/issues/91
    return escape(value);
  }

  // encoding / decoding according to RFC3986
  function strictEncodeURIComponent(string) {
    // see https://developer.mozilla.org/en-US/docs/JavaScript/Reference/Global_Objects/encodeURIComponent
    return encodeURIComponent(string)
      .replace(/[!'()*]/g, escapeForDumbFirefox36)
      .replace(/\*/g, '%2A');
  }
  URI.encode = strictEncodeURIComponent;
  URI.decode = decodeURIComponent;
  URI.iso8859 = function() {
    URI.encode = escape;
    URI.decode = unescape;
  };
  URI.unicode = function() {
    URI.encode = strictEncodeURIComponent;
    URI.decode = decodeURIComponent;
  };
  URI.characters = {
    pathname: {
      encode: {
        // RFC3986 2.1: For consistency, URI producers and normalizers should
        // use uppercase hexadecimal digits for all percent-encodings.
        expression: /%(24|26|2B|2C|3B|3D|3A|40)/ig,
        map: {
          // -._~!'()*
          '%24': '$',
          '%26': '&',
          '%2B': '+',
          '%2C': ',',
          '%3B': ';',
          '%3D': '=',
          '%3A': ':',
          '%40': '@'
        }
      },
      decode: {
        expression: /[\/\?#]/g,
        map: {
          '/': '%2F',
          '?': '%3F',
          '#': '%23'
        }
      }
    },
    reserved: {
      encode: {
        // RFC3986 2.1: For consistency, URI producers and normalizers should
        // use uppercase hexadecimal digits for all percent-encodings.
        expression: /%(21|23|24|26|27|28|29|2A|2B|2C|2F|3A|3B|3D|3F|40|5B|5D)/ig,
        map: {
          // gen-delims
          '%3A': ':',
          '%2F': '/',
          '%3F': '?',
          '%23': '#',
          '%5B': '[',
          '%5D': ']',
          '%40': '@',
          // sub-delims
          '%21': '!',
          '%24': '$',
          '%26': '&',
          '%27': '\'',
          '%28': '(',
          '%29': ')',
          '%2A': '*',
          '%2B': '+',
          '%2C': ',',
          '%3B': ';',
          '%3D': '='
        }
      }
    },
    urnpath: {
      // The characters under `encode` are the characters called out by RFC 2141 as being acceptable
      // for usage in a URN. RFC2141 also calls out "-", ".", and "_" as acceptable characters, but
      // these aren't encoded by encodeURIComponent, so we don't have to call them out here. Also
      // note that the colon character is not featured in the encoding map; this is because URI.js
      // gives the colons in URNs semantic meaning as the delimiters of path segements, and so it
      // should not appear unencoded in a segment itself.
      // See also the note above about RFC3986 and capitalalized hex digits.
      encode: {
        expression: /%(21|24|27|28|29|2A|2B|2C|3B|3D|40)/ig,
        map: {
          '%21': '!',
          '%24': '$',
          '%27': '\'',
          '%28': '(',
          '%29': ')',
          '%2A': '*',
          '%2B': '+',
          '%2C': ',',
          '%3B': ';',
          '%3D': '=',
          '%40': '@'
        }
      },
      // These characters are the characters called out by RFC2141 as "reserved" characters that
      // should never appear in a URN, plus the colon character (see note above).
      decode: {
        expression: /[\/\?#:]/g,
        map: {
          '/': '%2F',
          '?': '%3F',
          '#': '%23',
          ':': '%3A'
        }
      }
    }
  };
  URI.encodeQuery = function(string, escapeQuerySpace) {
    var escaped = URI.encode(string + '');
    if (escapeQuerySpace === undefined) {
      escapeQuerySpace = URI.escapeQuerySpace;
    }

    return escapeQuerySpace ? escaped.replace(/%20/g, '+') : escaped;
  };
  URI.decodeQuery = function(string, escapeQuerySpace) {
    string += '';
    if (escapeQuerySpace === undefined) {
      escapeQuerySpace = URI.escapeQuerySpace;
    }

    try {
      return URI.decode(escapeQuerySpace ? string.replace(/\+/g, '%20') : string);
    } catch(e) {
      // we're not going to mess with weird encodings,
      // give up and return the undecoded original string
      // see https://github.com/medialize/URI.js/issues/87
      // see https://github.com/medialize/URI.js/issues/92
      return string;
    }
  };
  // generate encode/decode path functions
  var _parts = {'encode':'encode', 'decode':'decode'};
  var _part;
  var generateAccessor = function(_group, _part) {
    return function(string) {
      try {
        return URI[_part](string + '').replace(URI.characters[_group][_part].expression, function(c) {
          return URI.characters[_group][_part].map[c];
        });
      } catch (e) {
        // we're not going to mess with weird encodings,
        // give up and return the undecoded original string
        // see https://github.com/medialize/URI.js/issues/87
        // see https://github.com/medialize/URI.js/issues/92
        return string;
      }
    };
  };

  for (_part in _parts) {
    URI[_part + 'PathSegment'] = generateAccessor('pathname', _parts[_part]);
    URI[_part + 'UrnPathSegment'] = generateAccessor('urnpath', _parts[_part]);
  }

  var generateSegmentedPathFunction = function(_sep, _codingFuncName, _innerCodingFuncName) {
    return function(string) {
      // Why pass in names of functions, rather than the function objects themselves? The
      // definitions of some functions (but in particular, URI.decode) will occasionally change due
      // to URI.js having ISO8859 and Unicode modes. Passing in the name and getting it will ensure
      // that the functions we use here are "fresh".
      var actualCodingFunc;
      if (!_innerCodingFuncName) {
        actualCodingFunc = URI[_codingFuncName];
      } else {
        actualCodingFunc = function(string) {
          return URI[_codingFuncName](URI[_innerCodingFuncName](string));
        };
      }

      var segments = (string + '').split(_sep);

      for (var i = 0, length = segments.length; i < length; i++) {
        segments[i] = actualCodingFunc(segments[i]);
      }

      return segments.join(_sep);
    };
  };

  // This takes place outside the above loop because we don't want, e.g., encodeUrnPath functions.
  URI.decodePath = generateSegmentedPathFunction('/', 'decodePathSegment');
  URI.decodeUrnPath = generateSegmentedPathFunction(':', 'decodeUrnPathSegment');
  URI.recodePath = generateSegmentedPathFunction('/', 'encodePathSegment', 'decode');
  URI.recodeUrnPath = generateSegmentedPathFunction(':', 'encodeUrnPathSegment', 'decode');

  URI.encodeReserved = generateAccessor('reserved', 'encode');

  URI.parse = function(string, parts) {
    var pos;
    if (!parts) {
      parts = {};
    }
    // [protocol"://"[username[":"password]"@"]hostname[":"port]"/"?][path]["?"querystring]["#"fragment]

    // extract fragment
    pos = string.indexOf('#');
    if (pos > -1) {
      // escaping?
      parts.fragment = string.substring(pos + 1) || null;
      string = string.substring(0, pos);
    }

    // extract query
    pos = string.indexOf('?');
    if (pos > -1) {
      // escaping?
      parts.query = string.substring(pos + 1) || null;
      string = string.substring(0, pos);
    }

    // extract protocol
    if (string.substring(0, 2) === '//') {
      // relative-scheme
      parts.protocol = null;
      string = string.substring(2);
      // extract "user:pass@host:port"
      string = URI.parseAuthority(string, parts);
    } else {
      pos = string.indexOf(':');
      if (pos > -1) {
        parts.protocol = string.substring(0, pos) || null;
        if (parts.protocol && !parts.protocol.match(URI.protocol_expression)) {
          // : may be within the path
          parts.protocol = undefined;
        } else if (string.substring(pos + 1, pos + 3) === '//') {
          string = string.substring(pos + 3);

          // extract "user:pass@host:port"
          string = URI.parseAuthority(string, parts);
        } else {
          string = string.substring(pos + 1);
          parts.urn = true;
        }
      }
    }

    // what's left must be the path
    parts.path = string;

    // and we're done
    return parts;
  };
  URI.parseHost = function(string, parts) {
    // Copy chrome, IE, opera backslash-handling behavior.
    // Back slashes before the query string get converted to forward slashes
    // See: https://github.com/joyent/node/blob/386fd24f49b0e9d1a8a076592a404168faeecc34/lib/url.js#L115-L124
    // See: https://code.google.com/p/chromium/issues/detail?id=25916
    // https://github.com/medialize/URI.js/pull/233
    string = string.replace(/\\/g, '/');

    // extract host:port
    var pos = string.indexOf('/');
    var bracketPos;
    var t;

    if (pos === -1) {
      pos = string.length;
    }

    if (string.charAt(0) === '[') {
      // IPv6 host - http://tools.ietf.org/html/draft-ietf-6man-text-addr-representation-04#section-6
      // I claim most client software breaks on IPv6 anyways. To simplify things, URI only accepts
      // IPv6+port in the format [2001:db8::1]:80 (for the time being)
      bracketPos = string.indexOf(']');
      parts.hostname = string.substring(1, bracketPos) || null;
      parts.port = string.substring(bracketPos + 2, pos) || null;
      if (parts.port === '/') {
        parts.port = null;
      }
    } else {
      var firstColon = string.indexOf(':');
      var firstSlash = string.indexOf('/');
      var nextColon = string.indexOf(':', firstColon + 1);
      if (nextColon !== -1 && (firstSlash === -1 || nextColon < firstSlash)) {
        // IPv6 host contains multiple colons - but no port
        // this notation is actually not allowed by RFC 3986, but we're a liberal parser
        parts.hostname = string.substring(0, pos) || null;
        parts.port = null;
      } else {
        t = string.substring(0, pos).split(':');
        parts.hostname = t[0] || null;
        parts.port = t[1] || null;
      }
    }

    if (parts.hostname && string.substring(pos).charAt(0) !== '/') {
      pos++;
      string = '/' + string;
    }

    return string.substring(pos) || '/';
  };
  URI.parseAuthority = function(string, parts) {
    string = URI.parseUserinfo(string, parts);
    return URI.parseHost(string, parts);
  };
  URI.parseUserinfo = function(string, parts) {
    // extract username:password
    var firstSlash = string.indexOf('/');
    var pos = string.lastIndexOf('@', firstSlash > -1 ? firstSlash : string.length - 1);
    var t;

    // authority@ must come before /path
    if (pos > -1 && (firstSlash === -1 || pos < firstSlash)) {
      t = string.substring(0, pos).split(':');
      parts.username = t[0] ? URI.decode(t[0]) : null;
      t.shift();
      parts.password = t[0] ? URI.decode(t.join(':')) : null;
      string = string.substring(pos + 1);
    } else {
      parts.username = null;
      parts.password = null;
    }

    return string;
  };
  URI.parseQuery = function(string, escapeQuerySpace) {
    if (!string) {
      return {};
    }

    // throw out the funky business - "?"[name"="value"&"]+
    string = string.replace(/&+/g, '&').replace(/^\?*&*|&+$/g, '');

    if (!string) {
      return {};
    }

    var items = {};
    var splits = string.split('&');
    var length = splits.length;
    var v, name, value;

    for (var i = 0; i < length; i++) {
      v = splits[i].split('=');
      name = URI.decodeQuery(v.shift(), escapeQuerySpace);
      // no "=" is null according to http://dvcs.w3.org/hg/url/raw-file/tip/Overview.html#collect-url-parameters
      value = v.length ? URI.decodeQuery(v.join('='), escapeQuerySpace) : null;

      if (hasOwn.call(items, name)) {
        if (typeof items[name] === 'string' || items[name] === null) {
          items[name] = [items[name]];
        }

        items[name].push(value);
      } else {
        items[name] = value;
      }
    }

    return items;
  };

  URI.build = function(parts) {
    var t = '';

    if (parts.protocol) {
      t += parts.protocol + ':';
    }

    if (!parts.urn && (t || parts.hostname)) {
      t += '//';
    }

    t += (URI.buildAuthority(parts) || '');

    if (typeof parts.path === 'string') {
      if (parts.path.charAt(0) !== '/' && typeof parts.hostname === 'string') {
        t += '/';
      }

      t += parts.path;
    }

    if (typeof parts.query === 'string' && parts.query) {
      t += '?' + parts.query;
    }

    if (typeof parts.fragment === 'string' && parts.fragment) {
      t += '#' + parts.fragment;
    }
    return t;
  };
  URI.buildHost = function(parts) {
    var t = '';

    if (!parts.hostname) {
      return '';
    } else if (URI.ip6_expression.test(parts.hostname)) {
      t += '[' + parts.hostname + ']';
    } else {
      t += parts.hostname;
    }

    if (parts.port) {
      t += ':' + parts.port;
    }

    return t;
  };
  URI.buildAuthority = function(parts) {
    return URI.buildUserinfo(parts) + URI.buildHost(parts);
  };
  URI.buildUserinfo = function(parts) {
    var t = '';

    if (parts.username) {
      t += URI.encode(parts.username);

      if (parts.password) {
        t += ':' + URI.encode(parts.password);
      }

      t += '@';
    }

    return t;
  };
  URI.buildQuery = function(data, duplicateQueryParameters, escapeQuerySpace) {
    // according to http://tools.ietf.org/html/rfc3986 or http://labs.apache.org/webarch/uri/rfc/rfc3986.html
    // being »-._~!$&'()*+,;=:@/?« %HEX and alnum are allowed
    // the RFC explicitly states ?/foo being a valid use case, no mention of parameter syntax!
    // URI.js treats the query string as being application/x-www-form-urlencoded
    // see http://www.w3.org/TR/REC-html40/interact/forms.html#form-content-type

    var t = '';
    var unique, key, i, length;
    for (key in data) {
      if (hasOwn.call(data, key) && key) {
        if (isArray(data[key])) {
          unique = {};
          for (i = 0, length = data[key].length; i < length; i++) {
            if (data[key][i] !== undefined && unique[data[key][i] + ''] === undefined) {
              t += '&' + URI.buildQueryParameter(key, data[key][i], escapeQuerySpace);
              if (duplicateQueryParameters !== true) {
                unique[data[key][i] + ''] = true;
              }
            }
          }
        } else if (data[key] !== undefined) {
          t += '&' + URI.buildQueryParameter(key, data[key], escapeQuerySpace);
        }
      }
    }

    return t.substring(1);
  };
  URI.buildQueryParameter = function(name, value, escapeQuerySpace) {
    // http://www.w3.org/TR/REC-html40/interact/forms.html#form-content-type -- application/x-www-form-urlencoded
    // don't append "=" for null values, according to http://dvcs.w3.org/hg/url/raw-file/tip/Overview.html#url-parameter-serialization
    return URI.encodeQuery(name, escapeQuerySpace) + (value !== null ? '=' + URI.encodeQuery(value, escapeQuerySpace) : '');
  };

  URI.addQuery = function(data, name, value) {
    if (typeof name === 'object') {
      for (var key in name) {
        if (hasOwn.call(name, key)) {
          URI.addQuery(data, key, name[key]);
        }
      }
    } else if (typeof name === 'string') {
      if (data[name] === undefined) {
        data[name] = value;
        return;
      } else if (typeof data[name] === 'string') {
        data[name] = [data[name]];
      }

      if (!isArray(value)) {
        value = [value];
      }

      data[name] = (data[name] || []).concat(value);
    } else {
      throw new TypeError('URI.addQuery() accepts an object, string as the name parameter');
    }
  };
  URI.removeQuery = function(data, name, value) {
    var i, length, key;

    if (isArray(name)) {
      for (i = 0, length = name.length; i < length; i++) {
        data[name[i]] = undefined;
      }
    } else if (getType(name) === 'RegExp') {
      for (key in data) {
        if (name.test(key)) {
          data[key] = undefined;
        }
      }
    } else if (typeof name === 'object') {
      for (key in name) {
        if (hasOwn.call(name, key)) {
          URI.removeQuery(data, key, name[key]);
        }
      }
    } else if (typeof name === 'string') {
      if (value !== undefined) {
        if (getType(value) === 'RegExp') {
          if (!isArray(data[name]) && value.test(data[name])) {
            data[name] = undefined;
          } else {
            data[name] = filterArrayValues(data[name], value);
          }
        } else if (data[name] === value) {
          data[name] = undefined;
        } else if (isArray(data[name])) {
          data[name] = filterArrayValues(data[name], value);
        }
      } else {
        data[name] = undefined;
      }
    } else {
      throw new TypeError('URI.removeQuery() accepts an object, string, RegExp as the first parameter');
    }
  };
  URI.hasQuery = function(data, name, value, withinArray) {
    if (typeof name === 'object') {
      for (var key in name) {
        if (hasOwn.call(name, key)) {
          if (!URI.hasQuery(data, key, name[key])) {
            return false;
          }
        }
      }

      return true;
    } else if (typeof name !== 'string') {
      throw new TypeError('URI.hasQuery() accepts an object, string as the name parameter');
    }

    switch (getType(value)) {
      case 'Undefined':
        // true if exists (but may be empty)
        return name in data; // data[name] !== undefined;

      case 'Boolean':
        // true if exists and non-empty
        var _booly = Boolean(isArray(data[name]) ? data[name].length : data[name]);
        return value === _booly;

      case 'Function':
        // allow complex comparison
        return !!value(data[name], name, data);

      case 'Array':
        if (!isArray(data[name])) {
          return false;
        }

        var op = withinArray ? arrayContains : arraysEqual;
        return op(data[name], value);

      case 'RegExp':
        if (!isArray(data[name])) {
          return Boolean(data[name] && data[name].match(value));
        }

        if (!withinArray) {
          return false;
        }

        return arrayContains(data[name], value);

      case 'Number':
        value = String(value);
        /* falls through */
      case 'String':
        if (!isArray(data[name])) {
          return data[name] === value;
        }

        if (!withinArray) {
          return false;
        }

        return arrayContains(data[name], value);

      default:
        throw new TypeError('URI.hasQuery() accepts undefined, boolean, string, number, RegExp, Function as the value parameter');
    }
  };


  URI.commonPath = function(one, two) {
    var length = Math.min(one.length, two.length);
    var pos;

    // find first non-matching character
    for (pos = 0; pos < length; pos++) {
      if (one.charAt(pos) !== two.charAt(pos)) {
        pos--;
        break;
      }
    }

    if (pos < 1) {
      return one.charAt(0) === two.charAt(0) && one.charAt(0) === '/' ? '/' : '';
    }

    // revert to last /
    if (one.charAt(pos) !== '/' || two.charAt(pos) !== '/') {
      pos = one.substring(0, pos).lastIndexOf('/');
    }

    return one.substring(0, pos + 1);
  };

  URI.withinString = function(string, callback, options) {
    options || (options = {});
    var _start = options.start || URI.findUri.start;
    var _end = options.end || URI.findUri.end;
    var _trim = options.trim || URI.findUri.trim;
    var _attributeOpen = /[a-z0-9-]=["']?$/i;

    _start.lastIndex = 0;
    while (true) {
      var match = _start.exec(string);
      if (!match) {
        break;
      }

      var start = match.index;
      if (options.ignoreHtml) {
        // attribut(e=["']?$)
        var attributeOpen = string.slice(Math.max(start - 3, 0), start);
        if (attributeOpen && _attributeOpen.test(attributeOpen)) {
          continue;
        }
      }

      var end = start + string.slice(start).search(_end);
      var slice = string.slice(start, end).replace(_trim, '');
      if (options.ignore && options.ignore.test(slice)) {
        continue;
      }

      end = start + slice.length;
      var result = callback(slice, start, end, string);
      string = string.slice(0, start) + result + string.slice(end);
      _start.lastIndex = start + result.length;
    }

    _start.lastIndex = 0;
    return string;
  };

  URI.ensureValidHostname = function(v) {
    // Theoretically URIs allow percent-encoding in Hostnames (according to RFC 3986)
    // they are not part of DNS and therefore ignored by URI.js

    if (v.match(URI.invalid_hostname_characters)) {
      // test punycode
      if (!punycode) {
        throw new TypeError('Hostname "' + v + '" contains characters other than [A-Z0-9.-] and Punycode.js is not available');
      }

      if (punycode.toASCII(v).match(URI.invalid_hostname_characters)) {
        throw new TypeError('Hostname "' + v + '" contains characters other than [A-Z0-9.-]');
      }
    }
  };

  // noConflict
  URI.noConflict = function(removeAll) {
    if (removeAll) {
      var unconflicted = {
        URI: this.noConflict()
      };

      if (root.URITemplate && typeof root.URITemplate.noConflict === 'function') {
        unconflicted.URITemplate = root.URITemplate.noConflict();
      }

      if (root.IPv6 && typeof root.IPv6.noConflict === 'function') {
        unconflicted.IPv6 = root.IPv6.noConflict();
      }

      if (root.SecondLevelDomains && typeof root.SecondLevelDomains.noConflict === 'function') {
        unconflicted.SecondLevelDomains = root.SecondLevelDomains.noConflict();
      }

      return unconflicted;
    } else if (root.URI === this) {
      root.URI = _URI;
    }

    return this;
  };

  p.build = function(deferBuild) {
    if (deferBuild === true) {
      this._deferred_build = true;
    } else if (deferBuild === undefined || this._deferred_build) {
      this._string = URI.build(this._parts);
      this._deferred_build = false;
    }

    return this;
  };

  p.clone = function() {
    return new URI(this);
  };

  p.valueOf = p.toString = function() {
    return this.build(false)._string;
  };


  function generateSimpleAccessor(_part){
    return function(v, build) {
      if (v === undefined) {
        return this._parts[_part] || '';
      } else {
        this._parts[_part] = v || null;
        this.build(!build);
        return this;
      }
    };
  }

  function generatePrefixAccessor(_part, _key){
    return function(v, build) {
      if (v === undefined) {
        return this._parts[_part] || '';
      } else {
        if (v !== null) {
          v = v + '';
          if (v.charAt(0) === _key) {
            v = v.substring(1);
          }
        }

        this._parts[_part] = v;
        this.build(!build);
        return this;
      }
    };
  }

  p.protocol = generateSimpleAccessor('protocol');
  p.username = generateSimpleAccessor('username');
  p.password = generateSimpleAccessor('password');
  p.hostname = generateSimpleAccessor('hostname');
  p.port = generateSimpleAccessor('port');
  p.query = generatePrefixAccessor('query', '?');
  p.fragment = generatePrefixAccessor('fragment', '#');

  p.search = function(v, build) {
    var t = this.query(v, build);
    return typeof t === 'string' && t.length ? ('?' + t) : t;
  };
  p.hash = function(v, build) {
    var t = this.fragment(v, build);
    return typeof t === 'string' && t.length ? ('#' + t) : t;
  };

  p.pathname = function(v, build) {
    if (v === undefined || v === true) {
      var res = this._parts.path || (this._parts.hostname ? '/' : '');
      return v ? (this._parts.urn ? URI.decodeUrnPath : URI.decodePath)(res) : res;
    } else {
      if (this._parts.urn) {
        this._parts.path = v ? URI.recodeUrnPath(v) : '';
      } else {
        this._parts.path = v ? URI.recodePath(v) : '/';
      }
      this.build(!build);
      return this;
    }
  };
  p.path = p.pathname;
  p.href = function(href, build) {
    var key;

    if (href === undefined) {
      return this.toString();
    }

    this._string = '';
    this._parts = URI._parts();

    var _URI = href instanceof URI;
    var _object = typeof href === 'object' && (href.hostname || href.path || href.pathname);
    if (href.nodeName) {
      var attribute = URI.getDomAttribute(href);
      href = href[attribute] || '';
      _object = false;
    }

    // window.location is reported to be an object, but it's not the sort
    // of object we're looking for:
    // * location.protocol ends with a colon
    // * location.query != object.search
    // * location.hash != object.fragment
    // simply serializing the unknown object should do the trick
    // (for location, not for everything...)
    if (!_URI && _object && href.pathname !== undefined) {
      href = href.toString();
    }

    if (typeof href === 'string' || href instanceof String) {
      this._parts = URI.parse(String(href), this._parts);
    } else if (_URI || _object) {
      var src = _URI ? href._parts : href;
      for (key in src) {
        if (hasOwn.call(this._parts, key)) {
          this._parts[key] = src[key];
        }
      }
    } else {
      throw new TypeError('invalid input');
    }

    this.build(!build);
    return this;
  };

  // identification accessors
  p.is = function(what) {
    var ip = false;
    var ip4 = false;
    var ip6 = false;
    var name = false;
    var sld = false;
    var idn = false;
    var punycode = false;
    var relative = !this._parts.urn;

    if (this._parts.hostname) {
      relative = false;
      ip4 = URI.ip4_expression.test(this._parts.hostname);
      ip6 = URI.ip6_expression.test(this._parts.hostname);
      ip = ip4 || ip6;
      name = !ip;
      sld = name && SLD && SLD.has(this._parts.hostname);
      idn = name && URI.idn_expression.test(this._parts.hostname);
      punycode = name && URI.punycode_expression.test(this._parts.hostname);
    }

    switch (what.toLowerCase()) {
      case 'relative':
        return relative;

      case 'absolute':
        return !relative;

      // hostname identification
      case 'domain':
      case 'name':
        return name;

      case 'sld':
        return sld;

      case 'ip':
        return ip;

      case 'ip4':
      case 'ipv4':
      case 'inet4':
        return ip4;

      case 'ip6':
      case 'ipv6':
      case 'inet6':
        return ip6;

      case 'idn':
        return idn;

      case 'url':
        return !this._parts.urn;

      case 'urn':
        return !!this._parts.urn;

      case 'punycode':
        return punycode;
    }

    return null;
  };

  // component specific input validation
  var _protocol = p.protocol;
  var _port = p.port;
  var _hostname = p.hostname;

  p.protocol = function(v, build) {
    if (v !== undefined) {
      if (v) {
        // accept trailing ://
        v = v.replace(/:(\/\/)?$/, '');

        if (!v.match(URI.protocol_expression)) {
          throw new TypeError('Protocol "' + v + '" contains characters other than [A-Z0-9.+-] or doesn\'t start with [A-Z]');
        }
      }
    }
    return _protocol.call(this, v, build);
  };
  p.scheme = p.protocol;
  p.port = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v !== undefined) {
      if (v === 0) {
        v = null;
      }

      if (v) {
        v += '';
        if (v.charAt(0) === ':') {
          v = v.substring(1);
        }

        if (v.match(/[^0-9]/)) {
          throw new TypeError('Port "' + v + '" contains characters other than [0-9]');
        }
      }
    }
    return _port.call(this, v, build);
  };
  p.hostname = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v !== undefined) {
      var x = {};
      var res = URI.parseHost(v, x);
      if (res !== '/') {
        throw new TypeError('Hostname "' + v + '" contains characters other than [A-Z0-9.-]');
      }

      v = x.hostname;
    }
    return _hostname.call(this, v, build);
  };

  // compound accessors
  p.host = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined) {
      return this._parts.hostname ? URI.buildHost(this._parts) : '';
    } else {
      var res = URI.parseHost(v, this._parts);
      if (res !== '/') {
        throw new TypeError('Hostname "' + v + '" contains characters other than [A-Z0-9.-]');
      }

      this.build(!build);
      return this;
    }
  };
  p.authority = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined) {
      return this._parts.hostname ? URI.buildAuthority(this._parts) : '';
    } else {
      var res = URI.parseAuthority(v, this._parts);
      if (res !== '/') {
        throw new TypeError('Hostname "' + v + '" contains characters other than [A-Z0-9.-]');
      }

      this.build(!build);
      return this;
    }
  };
  p.userinfo = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined) {
      if (!this._parts.username) {
        return '';
      }

      var t = URI.buildUserinfo(this._parts);
      return t.substring(0, t.length -1);
    } else {
      if (v[v.length-1] !== '@') {
        v += '@';
      }

      URI.parseUserinfo(v, this._parts);
      this.build(!build);
      return this;
    }
  };
  p.resource = function(v, build) {
    var parts;

    if (v === undefined) {
      return this.path() + this.search() + this.hash();
    }

    parts = URI.parse(v);
    this._parts.path = parts.path;
    this._parts.query = parts.query;
    this._parts.fragment = parts.fragment;
    this.build(!build);
    return this;
  };

  // fraction accessors
  p.subdomain = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    // convenience, return "www" from "www.example.org"
    if (v === undefined) {
      if (!this._parts.hostname || this.is('IP')) {
        return '';
      }

      // grab domain and add another segment
      var end = this._parts.hostname.length - this.domain().length - 1;
      return this._parts.hostname.substring(0, end) || '';
    } else {
      var e = this._parts.hostname.length - this.domain().length;
      var sub = this._parts.hostname.substring(0, e);
      var replace = new RegExp('^' + escapeRegEx(sub));

      if (v && v.charAt(v.length - 1) !== '.') {
        v += '.';
      }

      if (v) {
        URI.ensureValidHostname(v);
      }

      this._parts.hostname = this._parts.hostname.replace(replace, v);
      this.build(!build);
      return this;
    }
  };
  p.domain = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (typeof v === 'boolean') {
      build = v;
      v = undefined;
    }

    // convenience, return "example.org" from "www.example.org"
    if (v === undefined) {
      if (!this._parts.hostname || this.is('IP')) {
        return '';
      }

      // if hostname consists of 1 or 2 segments, it must be the domain
      var t = this._parts.hostname.match(/\./g);
      if (t && t.length < 2) {
        return this._parts.hostname;
      }

      // grab tld and add another segment
      var end = this._parts.hostname.length - this.tld(build).length - 1;
      end = this._parts.hostname.lastIndexOf('.', end -1) + 1;
      return this._parts.hostname.substring(end) || '';
    } else {
      if (!v) {
        throw new TypeError('cannot set domain empty');
      }

      URI.ensureValidHostname(v);

      if (!this._parts.hostname || this.is('IP')) {
        this._parts.hostname = v;
      } else {
        var replace = new RegExp(escapeRegEx(this.domain()) + '$');
        this._parts.hostname = this._parts.hostname.replace(replace, v);
      }

      this.build(!build);
      return this;
    }
  };
  p.tld = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (typeof v === 'boolean') {
      build = v;
      v = undefined;
    }

    // return "org" from "www.example.org"
    if (v === undefined) {
      if (!this._parts.hostname || this.is('IP')) {
        return '';
      }

      var pos = this._parts.hostname.lastIndexOf('.');
      var tld = this._parts.hostname.substring(pos + 1);

      if (build !== true && SLD && SLD.list[tld.toLowerCase()]) {
        return SLD.get(this._parts.hostname) || tld;
      }

      return tld;
    } else {
      var replace;

      if (!v) {
        throw new TypeError('cannot set TLD empty');
      } else if (v.match(/[^a-zA-Z0-9-]/)) {
        if (SLD && SLD.is(v)) {
          replace = new RegExp(escapeRegEx(this.tld()) + '$');
          this._parts.hostname = this._parts.hostname.replace(replace, v);
        } else {
          throw new TypeError('TLD "' + v + '" contains characters other than [A-Z0-9]');
        }
      } else if (!this._parts.hostname || this.is('IP')) {
        throw new ReferenceError('cannot set TLD on non-domain host');
      } else {
        replace = new RegExp(escapeRegEx(this.tld()) + '$');
        this._parts.hostname = this._parts.hostname.replace(replace, v);
      }

      this.build(!build);
      return this;
    }
  };
  p.directory = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined || v === true) {
      if (!this._parts.path && !this._parts.hostname) {
        return '';
      }

      if (this._parts.path === '/') {
        return '/';
      }

      var end = this._parts.path.length - this.filename().length - 1;
      var res = this._parts.path.substring(0, end) || (this._parts.hostname ? '/' : '');

      return v ? URI.decodePath(res) : res;

    } else {
      var e = this._parts.path.length - this.filename().length;
      var directory = this._parts.path.substring(0, e);
      var replace = new RegExp('^' + escapeRegEx(directory));

      // fully qualifier directories begin with a slash
      if (!this.is('relative')) {
        if (!v) {
          v = '/';
        }

        if (v.charAt(0) !== '/') {
          v = '/' + v;
        }
      }

      // directories always end with a slash
      if (v && v.charAt(v.length - 1) !== '/') {
        v += '/';
      }

      v = URI.recodePath(v);
      this._parts.path = this._parts.path.replace(replace, v);
      this.build(!build);
      return this;
    }
  };
  p.filename = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined || v === true) {
      if (!this._parts.path || this._parts.path === '/') {
        return '';
      }

      var pos = this._parts.path.lastIndexOf('/');
      var res = this._parts.path.substring(pos+1);

      return v ? URI.decodePathSegment(res) : res;
    } else {
      var mutatedDirectory = false;

      if (v.charAt(0) === '/') {
        v = v.substring(1);
      }

      if (v.match(/\.?\//)) {
        mutatedDirectory = true;
      }

      var replace = new RegExp(escapeRegEx(this.filename()) + '$');
      v = URI.recodePath(v);
      this._parts.path = this._parts.path.replace(replace, v);

      if (mutatedDirectory) {
        this.normalizePath(build);
      } else {
        this.build(!build);
      }

      return this;
    }
  };
  p.suffix = function(v, build) {
    if (this._parts.urn) {
      return v === undefined ? '' : this;
    }

    if (v === undefined || v === true) {
      if (!this._parts.path || this._parts.path === '/') {
        return '';
      }

      var filename = this.filename();
      var pos = filename.lastIndexOf('.');
      var s, res;

      if (pos === -1) {
        return '';
      }

      // suffix may only contain alnum characters (yup, I made this up.)
      s = filename.substring(pos+1);
      res = (/^[a-z0-9%]+$/i).test(s) ? s : '';
      return v ? URI.decodePathSegment(res) : res;
    } else {
      if (v.charAt(0) === '.') {
        v = v.substring(1);
      }

      var suffix = this.suffix();
      var replace;

      if (!suffix) {
        if (!v) {
          return this;
        }

        this._parts.path += '.' + URI.recodePath(v);
      } else if (!v) {
        replace = new RegExp(escapeRegEx('.' + suffix) + '$');
      } else {
        replace = new RegExp(escapeRegEx(suffix) + '$');
      }

      if (replace) {
        v = URI.recodePath(v);
        this._parts.path = this._parts.path.replace(replace, v);
      }

      this.build(!build);
      return this;
    }
  };
  p.segment = function(segment, v, build) {
    var separator = this._parts.urn ? ':' : '/';
    var path = this.path();
    var absolute = path.substring(0, 1) === '/';
    var segments = path.split(separator);

    if (segment !== undefined && typeof segment !== 'number') {
      build = v;
      v = segment;
      segment = undefined;
    }

    if (segment !== undefined && typeof segment !== 'number') {
      throw new Error('Bad segment "' + segment + '", must be 0-based integer');
    }

    if (absolute) {
      segments.shift();
    }

    if (segment < 0) {
      // allow negative indexes to address from the end
      segment = Math.max(segments.length + segment, 0);
    }

    if (v === undefined) {
      /*jshint laxbreak: true */
      return segment === undefined
        ? segments
        : segments[segment];
      /*jshint laxbreak: false */
    } else if (segment === null || segments[segment] === undefined) {
      if (isArray(v)) {
        segments = [];
        // collapse empty elements within array
        for (var i=0, l=v.length; i < l; i++) {
          if (!v[i].length && (!segments.length || !segments[segments.length -1].length)) {
            continue;
          }

          if (segments.length && !segments[segments.length -1].length) {
            segments.pop();
          }

          segments.push(v[i]);
        }
      } else if (v || typeof v === 'string') {
        if (segments[segments.length -1] === '') {
          // empty trailing elements have to be overwritten
          // to prevent results such as /foo//bar
          segments[segments.length -1] = v;
        } else {
          segments.push(v);
        }
      }
    } else {
      if (v) {
        segments[segment] = v;
      } else {
        segments.splice(segment, 1);
      }
    }

    if (absolute) {
      segments.unshift('');
    }

    return this.path(segments.join(separator), build);
  };
  p.segmentCoded = function(segment, v, build) {
    var segments, i, l;

    if (typeof segment !== 'number') {
      build = v;
      v = segment;
      segment = undefined;
    }

    if (v === undefined) {
      segments = this.segment(segment, v, build);
      if (!isArray(segments)) {
        segments = segments !== undefined ? URI.decode(segments) : undefined;
      } else {
        for (i = 0, l = segments.length; i < l; i++) {
          segments[i] = URI.decode(segments[i]);
        }
      }

      return segments;
    }

    if (!isArray(v)) {
      v = (typeof v === 'string' || v instanceof String) ? URI.encode(v) : v;
    } else {
      for (i = 0, l = v.length; i < l; i++) {
        v[i] = URI.encode(v[i]);
      }
    }

    return this.segment(segment, v, build);
  };

  // mutating query string
  var q = p.query;
  p.query = function(v, build) {
    if (v === true) {
      return URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);
    } else if (typeof v === 'function') {
      var data = URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);
      var result = v.call(this, data);
      this._parts.query = URI.buildQuery(result || data, this._parts.duplicateQueryParameters, this._parts.escapeQuerySpace);
      this.build(!build);
      return this;
    } else if (v !== undefined && typeof v !== 'string') {
      this._parts.query = URI.buildQuery(v, this._parts.duplicateQueryParameters, this._parts.escapeQuerySpace);
      this.build(!build);
      return this;
    } else {
      return q.call(this, v, build);
    }
  };
  p.setQuery = function(name, value, build) {
    var data = URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);

    if (typeof name === 'string' || name instanceof String) {
      data[name] = value !== undefined ? value : null;
    } else if (typeof name === 'object') {
      for (var key in name) {
        if (hasOwn.call(name, key)) {
          data[key] = name[key];
        }
      }
    } else {
      throw new TypeError('URI.addQuery() accepts an object, string as the name parameter');
    }

    this._parts.query = URI.buildQuery(data, this._parts.duplicateQueryParameters, this._parts.escapeQuerySpace);
    if (typeof name !== 'string') {
      build = value;
    }

    this.build(!build);
    return this;
  };
  p.addQuery = function(name, value, build) {
    var data = URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);
    URI.addQuery(data, name, value === undefined ? null : value);
    this._parts.query = URI.buildQuery(data, this._parts.duplicateQueryParameters, this._parts.escapeQuerySpace);
    if (typeof name !== 'string') {
      build = value;
    }

    this.build(!build);
    return this;
  };
  p.removeQuery = function(name, value, build) {
    var data = URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);
    URI.removeQuery(data, name, value);
    this._parts.query = URI.buildQuery(data, this._parts.duplicateQueryParameters, this._parts.escapeQuerySpace);
    if (typeof name !== 'string') {
      build = value;
    }

    this.build(!build);
    return this;
  };
  p.hasQuery = function(name, value, withinArray) {
    var data = URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace);
    return URI.hasQuery(data, name, value, withinArray);
  };
  p.setSearch = p.setQuery;
  p.addSearch = p.addQuery;
  p.removeSearch = p.removeQuery;
  p.hasSearch = p.hasQuery;

  // sanitizing URLs
  p.normalize = function() {
    if (this._parts.urn) {
      return this
        .normalizeProtocol(false)
        .normalizePath(false)
        .normalizeQuery(false)
        .normalizeFragment(false)
        .build();
    }

    return this
      .normalizeProtocol(false)
      .normalizeHostname(false)
      .normalizePort(false)
      .normalizePath(false)
      .normalizeQuery(false)
      .normalizeFragment(false)
      .build();
  };
  p.normalizeProtocol = function(build) {
    if (typeof this._parts.protocol === 'string') {
      this._parts.protocol = this._parts.protocol.toLowerCase();
      this.build(!build);
    }

    return this;
  };
  p.normalizeHostname = function(build) {
    if (this._parts.hostname) {
      if (this.is('IDN') && punycode) {
        this._parts.hostname = punycode.toASCII(this._parts.hostname);
      } else if (this.is('IPv6') && IPv6) {
        this._parts.hostname = IPv6.best(this._parts.hostname);
      }

      this._parts.hostname = this._parts.hostname.toLowerCase();
      this.build(!build);
    }

    return this;
  };
  p.normalizePort = function(build) {
    // remove port of it's the protocol's default
    if (typeof this._parts.protocol === 'string' && this._parts.port === URI.defaultPorts[this._parts.protocol]) {
      this._parts.port = null;
      this.build(!build);
    }

    return this;
  };
  p.normalizePath = function(build) {
    var _path = this._parts.path;
    if (!_path) {
      return this;
    }

    if (this._parts.urn) {
      this._parts.path = URI.recodeUrnPath(this._parts.path);
      this.build(!build);
      return this;
    }

    if (this._parts.path === '/') {
      return this;
    }

    var _was_relative;
    var _leadingParents = '';
    var _parent, _pos;

    // handle relative paths
    if (_path.charAt(0) !== '/') {
      _was_relative = true;
      _path = '/' + _path;
    }

    // handle relative files (as opposed to directories)
    if (_path.slice(-3) === '/..' || _path.slice(-2) === '/.') {
      _path += '/';
    }

    // resolve simples
    _path = _path
      .replace(/(\/(\.\/)+)|(\/\.$)/g, '/')
      .replace(/\/{2,}/g, '/');

    // remember leading parents
    if (_was_relative) {
      _leadingParents = _path.substring(1).match(/^(\.\.\/)+/) || '';
      if (_leadingParents) {
        _leadingParents = _leadingParents[0];
      }
    }

    // resolve parents
    while (true) {
      _parent = _path.indexOf('/..');
      if (_parent === -1) {
        // no more ../ to resolve
        break;
      } else if (_parent === 0) {
        // top level cannot be relative, skip it
        _path = _path.substring(3);
        continue;
      }

      _pos = _path.substring(0, _parent).lastIndexOf('/');
      if (_pos === -1) {
        _pos = _parent;
      }
      _path = _path.substring(0, _pos) + _path.substring(_parent + 3);
    }

    // revert to relative
    if (_was_relative && this.is('relative')) {
      _path = _leadingParents + _path.substring(1);
    }

    _path = URI.recodePath(_path);
    this._parts.path = _path;
    this.build(!build);
    return this;
  };
  p.normalizePathname = p.normalizePath;
  p.normalizeQuery = function(build) {
    if (typeof this._parts.query === 'string') {
      if (!this._parts.query.length) {
        this._parts.query = null;
      } else {
        this.query(URI.parseQuery(this._parts.query, this._parts.escapeQuerySpace));
      }

      this.build(!build);
    }

    return this;
  };
  p.normalizeFragment = function(build) {
    if (!this._parts.fragment) {
      this._parts.fragment = null;
      this.build(!build);
    }

    return this;
  };
  p.normalizeSearch = p.normalizeQuery;
  p.normalizeHash = p.normalizeFragment;

  p.iso8859 = function() {
    // expect unicode input, iso8859 output
    var e = URI.encode;
    var d = URI.decode;

    URI.encode = escape;
    URI.decode = decodeURIComponent;
    try {
      this.normalize();
    } finally {
      URI.encode = e;
      URI.decode = d;
    }
    return this;
  };

  p.unicode = function() {
    // expect iso8859 input, unicode output
    var e = URI.encode;
    var d = URI.decode;

    URI.encode = strictEncodeURIComponent;
    URI.decode = unescape;
    try {
      this.normalize();
    } finally {
      URI.encode = e;
      URI.decode = d;
    }
    return this;
  };

  p.readable = function() {
    var uri = this.clone();
    // removing username, password, because they shouldn't be displayed according to RFC 3986
    uri.username('').password('').normalize();
    var t = '';
    if (uri._parts.protocol) {
      t += uri._parts.protocol + '://';
    }

    if (uri._parts.hostname) {
      if (uri.is('punycode') && punycode) {
        t += punycode.toUnicode(uri._parts.hostname);
        if (uri._parts.port) {
          t += ':' + uri._parts.port;
        }
      } else {
        t += uri.host();
      }
    }

    if (uri._parts.hostname && uri._parts.path && uri._parts.path.charAt(0) !== '/') {
      t += '/';
    }

    t += uri.path(true);
    if (uri._parts.query) {
      var q = '';
      for (var i = 0, qp = uri._parts.query.split('&'), l = qp.length; i < l; i++) {
        var kv = (qp[i] || '').split('=');
        q += '&' + URI.decodeQuery(kv[0], this._parts.escapeQuerySpace)
          .replace(/&/g, '%26');

        if (kv[1] !== undefined) {
          q += '=' + URI.decodeQuery(kv[1], this._parts.escapeQuerySpace)
            .replace(/&/g, '%26');
        }
      }
      t += '?' + q.substring(1);
    }

    t += URI.decodeQuery(uri.hash(), true);
    return t;
  };

  // resolving relative and absolute URLs
  p.absoluteTo = function(base) {
    var resolved = this.clone();
    var properties = ['protocol', 'username', 'password', 'hostname', 'port'];
    var basedir, i, p;

    if (this._parts.urn) {
      throw new Error('URNs do not have any generally defined hierarchical components');
    }

    if (!(base instanceof URI)) {
      base = new URI(base);
    }

    if (!resolved._parts.protocol) {
      resolved._parts.protocol = base._parts.protocol;
    }

    if (this._parts.hostname) {
      return resolved;
    }

    for (i = 0; (p = properties[i]); i++) {
      resolved._parts[p] = base._parts[p];
    }

    if (!resolved._parts.path) {
      resolved._parts.path = base._parts.path;
      if (!resolved._parts.query) {
        resolved._parts.query = base._parts.query;
      }
    } else if (resolved._parts.path.substring(-2) === '..') {
      resolved._parts.path += '/';
    }

    if (resolved.path().charAt(0) !== '/') {
      basedir = base.directory();
      basedir = basedir ? basedir : base.path().indexOf('/') === 0 ? '/' : '';
      resolved._parts.path = (basedir ? (basedir + '/') : '') + resolved._parts.path;
      resolved.normalizePath();
    }

    resolved.build();
    return resolved;
  };
  p.relativeTo = function(base) {
    var relative = this.clone().normalize();
    var relativeParts, baseParts, common, relativePath, basePath;

    if (relative._parts.urn) {
      throw new Error('URNs do not have any generally defined hierarchical components');
    }

    base = new URI(base).normalize();
    relativeParts = relative._parts;
    baseParts = base._parts;
    relativePath = relative.path();
    basePath = base.path();

    if (relativePath.charAt(0) !== '/') {
      throw new Error('URI is already relative');
    }

    if (basePath.charAt(0) !== '/') {
      throw new Error('Cannot calculate a URI relative to another relative URI');
    }

    if (relativeParts.protocol === baseParts.protocol) {
      relativeParts.protocol = null;
    }

    if (relativeParts.username !== baseParts.username || relativeParts.password !== baseParts.password) {
      return relative.build();
    }

    if (relativeParts.protocol !== null || relativeParts.username !== null || relativeParts.password !== null) {
      return relative.build();
    }

    if (relativeParts.hostname === baseParts.hostname && relativeParts.port === baseParts.port) {
      relativeParts.hostname = null;
      relativeParts.port = null;
    } else {
      return relative.build();
    }

    if (relativePath === basePath) {
      relativeParts.path = '';
      return relative.build();
    }

    // determine common sub path
    common = URI.commonPath(relativePath, basePath);

    // If the paths have nothing in common, return a relative URL with the absolute path.
    if (!common) {
      return relative.build();
    }

    var parents = baseParts.path
      .substring(common.length)
      .replace(/[^\/]*$/, '')
      .replace(/.*?\//g, '../');

    relativeParts.path = (parents + relativeParts.path.substring(common.length)) || './';

    return relative.build();
  };

  // comparing URIs
  p.equals = function(uri) {
    var one = this.clone();
    var two = new URI(uri);
    var one_map = {};
    var two_map = {};
    var checked = {};
    var one_query, two_query, key;

    one.normalize();
    two.normalize();

    // exact match
    if (one.toString() === two.toString()) {
      return true;
    }

    // extract query string
    one_query = one.query();
    two_query = two.query();
    one.query('');
    two.query('');

    // definitely not equal if not even non-query parts match
    if (one.toString() !== two.toString()) {
      return false;
    }

    // query parameters have the same length, even if they're permuted
    if (one_query.length !== two_query.length) {
      return false;
    }

    one_map = URI.parseQuery(one_query, this._parts.escapeQuerySpace);
    two_map = URI.parseQuery(two_query, this._parts.escapeQuerySpace);

    for (key in one_map) {
      if (hasOwn.call(one_map, key)) {
        if (!isArray(one_map[key])) {
          if (one_map[key] !== two_map[key]) {
            return false;
          }
        } else if (!arraysEqual(one_map[key], two_map[key])) {
          return false;
        }

        checked[key] = true;
      }
    }

    for (key in two_map) {
      if (hasOwn.call(two_map, key)) {
        if (!checked[key]) {
          // two contains a parameter not present in one
          return false;
        }
      }
    }

    return true;
  };

  // state
  p.duplicateQueryParameters = function(v) {
    this._parts.duplicateQueryParameters = !!v;
    return this;
  };

  p.escapeQuerySpace = function(v) {
    this._parts.escapeQuerySpace = !!v;
    return this;
  };

  return URI;
}));

},{"./IPv6":9,"./SecondLevelDomains":10,"./punycode":12}],12:[function(require,module,exports){
(function (global){
/*! http://mths.be/punycode v1.2.3 by @mathias */
;(function(root) {

	/** Detect free variables */
	var freeExports = typeof exports == 'object' && exports;
	var freeModule = typeof module == 'object' && module &&
		module.exports == freeExports && module;
	var freeGlobal = typeof global == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
		root = freeGlobal;
	}

	/**
	 * The `punycode` object.
	 * @name punycode
	 * @type Object
	 */
	var punycode,

	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	tMin = 1,
	tMax = 26,
	skew = 38,
	damp = 700,
	initialBias = 72,
	initialN = 128, // 0x80
	delimiter = '-', // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	regexNonASCII = /[^ -~]/, // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /\x2E|\u3002|\uFF0E|\uFF61/g, // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},

	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	floor = Math.floor,
	stringFromCharCode = String.fromCharCode,

	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
	 * A generic error utility function.
	 * @private
	 * @param {String} type The error type.
	 * @returns {Error} Throws a `RangeError` with the applicable error message.
	 */
	function error(type) {
		throw RangeError(errors[type]);
	}

	/**
	 * A generic `Array#map` utility function.
	 * @private
	 * @param {Array} array The array to iterate over.
	 * @param {Function} callback The function that gets called for every array
	 * item.
	 * @returns {Array} A new array of values returned by the callback function.
	 */
	function map(array, fn) {
		var length = array.length;
		while (length--) {
			array[length] = fn(array[length]);
		}
		return array;
	}

	/**
	 * A simple `Array#map`-like wrapper to work with domain name strings.
	 * @private
	 * @param {String} domain The domain name.
	 * @param {Function} callback The function that gets called for every
	 * character.
	 * @returns {Array} A new string of characters returned by the callback
	 * function.
	 */
	function mapDomain(string, fn) {
		return map(string.split(regexSeparators), fn).join('.');
	}

	/**
	 * Creates an array containing the numeric code points of each Unicode
	 * character in the string. While JavaScript uses UCS-2 internally,
	 * this function will convert a pair of surrogate halves (each of which
	 * UCS-2 exposes as separate characters) into a single code point,
	 * matching UTF-16.
	 * @see `punycode.ucs2.encode`
	 * @see <http://mathiasbynens.be/notes/javascript-encoding>
	 * @memberOf punycode.ucs2
	 * @name decode
	 * @param {String} string The Unicode input string (UCS-2).
	 * @returns {Array} The new array of code points.
	 */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
	 * Creates a string based on an array of numeric code points.
	 * @see `punycode.ucs2.decode`
	 * @memberOf punycode.ucs2
	 * @name encode
	 * @param {Array} codePoints The array of numeric code points.
	 * @returns {String} The new Unicode string (UCS-2).
	 */
	function ucs2encode(array) {
		return map(array, function(value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
	 * Converts a basic code point into a digit/integer.
	 * @see `digitToBasic()`
	 * @private
	 * @param {Number} codePoint The basic numeric code point value.
	 * @returns {Number} The numeric value of a basic code point (for use in
	 * representing integers) in the range `0` to `base - 1`, or `base` if
	 * the code point does not represent a value.
	 */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
	 * Converts a digit/integer into a basic code point.
	 * @see `basicToDigit()`
	 * @private
	 * @param {Number} digit The numeric value of a basic code point.
	 * @returns {Number} The basic code point whose value (when used for
	 * representing integers) is `digit`, which needs to be in the range
	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
	 * used; else, the lowercase form is used. The behavior is undefined
	 * if `flag` is non-zero and `digit` has no uppercase form.
	 */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
	 * Bias adaptation function as per section 3.4 of RFC 3492.
	 * http://tools.ietf.org/html/rfc3492#section-3.4
	 * @private
	 */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The Punycode string of ASCII-only symbols.
	 * @returns {String} The resulting string of Unicode symbols.
	 */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,
		    length,
		    /** Cached calculation results */
		    baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;

			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);

		}

		return ucs2encode(output);
	}

	/**
	 * Converts a string of Unicode symbols to a Punycode string of ASCII-only
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The string of Unicode symbols.
	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
	 */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],
		    /** `inputLength` will hold the number of code points in `input`. */
		    inputLength,
		    /** Cached calculation results */
		    handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base; /* no condition */; k += base) {
						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(
							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
						);
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;

		}
		return output.join('');
	}

	/**
	 * Converts a Punycode string representing a domain name to Unicode. Only the
	 * Punycoded parts of the domain name will be converted, i.e. it doesn't
	 * matter if you call it on a string that has already been converted to
	 * Unicode.
	 * @memberOf punycode
	 * @param {String} domain The Punycode domain name to convert to Unicode.
	 * @returns {String} The Unicode representation of the given Punycode
	 * string.
	 */
	function toUnicode(domain) {
		return mapDomain(domain, function(string) {
			return regexPunycode.test(string)
				? decode(string.slice(4).toLowerCase())
				: string;
		});
	}

	/**
	 * Converts a Unicode string representing a domain name to Punycode. Only the
	 * non-ASCII parts of the domain name will be converted, i.e. it doesn't
	 * matter if you call it with a domain that's already in ASCII.
	 * @memberOf punycode
	 * @param {String} domain The domain name to convert, as a Unicode string.
	 * @returns {String} The Punycode representation of the given domain name.
	 */
	function toASCII(domain) {
		return mapDomain(domain, function(string) {
			return regexNonASCII.test(string)
				? 'xn--' + encode(string)
				: string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
		 * A string representing the current Punycode.js version number.
		 * @memberOf punycode
		 * @type String
		 */
		'version': '1.2.3',
		/**
		 * An object of methods to convert from JavaScript's internal character
		 * representation (UCS-2) to Unicode code points, and back.
		 * @see <http://mathiasbynens.be/notes/javascript-encoding>
		 * @memberOf punycode
		 * @type Object
		 */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define(function() {
			return punycode;
		});
	}	else if (freeExports && !freeExports.nodeType) {
		if (freeModule) { // in Node.js or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else { // in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else { // in Rhino or a web browser
		root.punycode = punycode;
	}

}(this));

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],13:[function(require,module,exports){

},{}],14:[function(require,module,exports){
/*
    HTTP Hawk Authentication Scheme
    Copyright (c) 2012-2014, Eran Hammer <eran@hammer.io>
    BSD Licensed
*/


// Declare namespace

var hawk = {
    internals: {}
};


hawk.client = {

    // Generate an Authorization header for a given request

    /*
        uri: 'http://example.com/resource?a=b' or object generated by hawk.utils.parseUri()
        method: HTTP verb (e.g. 'GET', 'POST')
        options: {

            // Required

            credentials: {
                id: 'dh37fgj492je',
                key: 'aoijedoaijsdlaksjdl',
                algorithm: 'sha256'                                 // 'sha1', 'sha256'
            },

            // Optional

            ext: 'application-specific',                        // Application specific data sent via the ext attribute
            timestamp: Date.now() / 1000,                       // A pre-calculated timestamp in seconds
            nonce: '2334f34f',                                  // A pre-generated nonce
            localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
            payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
            contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
            hash: 'U4MKKSmiVxk37JCCrAVIjV=',                    // Pre-calculated payload hash
            app: '24s23423f34dx',                               // Oz application id
            dlg: '234sz34tww3sd'                                // Oz delegated-by application id
        }
    */

    header: function (uri, method, options) {

        var result = {
            field: '',
            artifacts: {}
        };

        // Validate inputs

        if (!uri || (typeof uri !== 'string' && typeof uri !== 'object') ||
            !method || typeof method !== 'string' ||
            !options || typeof options !== 'object') {

            result.err = 'Invalid argument type';
            return result;
        }

        // Application time

        var timestamp = options.timestamp || hawk.utils.now(options.localtimeOffsetMsec);

        // Validate credentials

        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {

            result.err = 'Invalid credentials object';
            return result;
        }

        if (hawk.crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            result.err = 'Unknown algorithm';
            return result;
        }

        // Parse URI

        if (typeof uri === 'string') {
            uri = hawk.utils.parseUri(uri);
        }

        // Calculate signature

        var artifacts = {
            ts: timestamp,
            nonce: options.nonce || hawk.utils.randomString(6),
            method: method,
            resource: uri.resource,
            host: uri.host,
            port: uri.port,
            hash: options.hash,
            ext: options.ext,
            app: options.app,
            dlg: options.dlg
        };

        result.artifacts = artifacts;

        // Calculate payload hash

        if (!artifacts.hash &&
            (options.payload || options.payload === '')) {

            artifacts.hash = hawk.crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
        }

        var mac = hawk.crypto.calculateMac('header', credentials, artifacts);

        // Construct header

        var hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== '';       // Other falsey values allowed
        var header = 'Hawk id="' + credentials.id +
                     '", ts="' + artifacts.ts +
                     '", nonce="' + artifacts.nonce +
                     (artifacts.hash ? '", hash="' + artifacts.hash : '') +
                     (hasExt ? '", ext="' + hawk.utils.escapeHeaderAttribute(artifacts.ext) : '') +
                     '", mac="' + mac + '"';

        if (artifacts.app) {
            header += ', app="' + artifacts.app +
                      (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"';
        }

        result.field = header;

        return result;
    },

    // Generate a bewit value for a given URI

    /*
        uri: 'http://example.com/resource?a=b'
        options: {

            // Required

            credentials: {
            id: 'dh37fgj492je',
            key: 'aoijedoaijsdlaksjdl',
            algorithm: 'sha256'                             // 'sha1', 'sha256'
            },
            ttlSec: 60 * 60,                                    // TTL in seconds

            // Optional

            ext: 'application-specific',                        // Application specific data sent via the ext attribute
            localtimeOffsetMsec: 400                            // Time offset to sync with server time
         };
    */

    bewit: function (uri, options) {

        // Validate inputs

        if (!uri ||
            (typeof uri !== 'string') ||
            !options ||
            typeof options !== 'object' ||
            !options.ttlSec) {

            return '';
        }

        options.ext = (options.ext === null || options.ext === undefined ? '' : options.ext);       // Zero is valid value

        // Application time

        var now = hawk.utils.now(options.localtimeOffsetMsec);

        // Validate credentials

        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {

            return '';
        }

        if (hawk.crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return '';
        }

        // Parse URI

        uri = hawk.utils.parseUri(uri);

        // Calculate signature

        var exp = now + options.ttlSec;
        var mac = hawk.crypto.calculateMac('bewit', credentials, {
            ts: exp,
            nonce: '',
            method: 'GET',
            resource: uri.resource,                            // Maintain trailing '?' and query params
            host: uri.host,
            port: uri.port,
            ext: options.ext
        });

        // Construct bewit: id\exp\mac\ext

        var bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + options.ext;
        return hawk.utils.base64urlEncode(bewit);
    },

    // Validate server response

    /*
        request:    object created via 'new XMLHttpRequest()' after response received
        artifacts:  object received from header().artifacts
        options: {
            payload:    optional payload received
            required:   specifies if a Server-Authorization header is required. Defaults to 'false'
        }
    */

    authenticate: function (request, credentials, artifacts, options) {

        options = options || {};

        var getHeader = function (name) {

            return request.getResponseHeader ? request.getResponseHeader(name) : request.getHeader(name);
        };

        var wwwAuthenticate = getHeader('www-authenticate');
        if (wwwAuthenticate) {

            // Parse HTTP WWW-Authenticate header

            var wwwAttributes = hawk.utils.parseAuthorizationHeader(wwwAuthenticate, ['ts', 'tsm', 'error']);
            if (!wwwAttributes) {
                return false;
            }

            if (wwwAttributes.ts) {
                var tsm = hawk.crypto.calculateTsMac(wwwAttributes.ts, credentials);
                if (tsm !== wwwAttributes.tsm) {
                    return false;
                }

                hawk.utils.setNtpOffset(wwwAttributes.ts - Math.floor((new Date()).getTime() / 1000));     // Keep offset at 1 second precision
            }
        }

        // Parse HTTP Server-Authorization header

        var serverAuthorization = getHeader('server-authorization');
        if (!serverAuthorization &&
            !options.required) {

            return true;
        }

        var attributes = hawk.utils.parseAuthorizationHeader(serverAuthorization, ['mac', 'ext', 'hash']);
        if (!attributes) {
            return false;
        }

        var modArtifacts = {
            ts: artifacts.ts,
            nonce: artifacts.nonce,
            method: artifacts.method,
            resource: artifacts.resource,
            host: artifacts.host,
            port: artifacts.port,
            hash: attributes.hash,
            ext: attributes.ext,
            app: artifacts.app,
            dlg: artifacts.dlg
        };

        var mac = hawk.crypto.calculateMac('response', credentials, modArtifacts);
        if (mac !== attributes.mac) {
            return false;
        }

        if (!options.payload &&
            options.payload !== '') {

            return true;
        }

        if (!attributes.hash) {
            return false;
        }

        var calculatedHash = hawk.crypto.calculatePayloadHash(options.payload, credentials.algorithm, getHeader('content-type'));
        return (calculatedHash === attributes.hash);
    },

    message: function (host, port, message, options) {

        // Validate inputs

        if (!host || typeof host !== 'string' ||
            !port || typeof port !== 'number' ||
            message === null || message === undefined || typeof message !== 'string' ||
            !options || typeof options !== 'object') {

            return null;
        }

        // Application time

        var timestamp = options.timestamp || hawk.utils.now(options.localtimeOffsetMsec);

        // Validate credentials

        var credentials = options.credentials;
        if (!credentials ||
            !credentials.id ||
            !credentials.key ||
            !credentials.algorithm) {

            // Invalid credential object
            return null;
        }

        if (hawk.crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return null;
        }

        // Calculate signature

        var artifacts = {
            ts: timestamp,
            nonce: options.nonce || hawk.utils.randomString(6),
            host: host,
            port: port,
            hash: hawk.crypto.calculatePayloadHash(message, credentials.algorithm)
        };

        // Construct authorization

        var result = {
            id: credentials.id,
            ts: artifacts.ts,
            nonce: artifacts.nonce,
            hash: artifacts.hash,
            mac: hawk.crypto.calculateMac('message', credentials, artifacts)
        };

        return result;
    },

    authenticateTimestamp: function (message, credentials, updateClock) {           // updateClock defaults to true

        var tsm = hawk.crypto.calculateTsMac(message.ts, credentials);
        if (tsm !== message.tsm) {
            return false;
        }

        if (updateClock !== false) {
            hawk.utils.setNtpOffset(message.ts - Math.floor((new Date()).getTime() / 1000));    // Keep offset at 1 second precision
        }

        return true;
    }
};


hawk.crypto = {

    headerVersion: '1',

    algorithms: ['sha1', 'sha256'],

    calculateMac: function (type, credentials, options) {

        var normalized = hawk.crypto.generateNormalizedString(type, options);

        var hmac = CryptoJS['Hmac' + credentials.algorithm.toUpperCase()](normalized, credentials.key);
        return hmac.toString(CryptoJS.enc.Base64);
    },

    generateNormalizedString: function (type, options) {

        var normalized = 'hawk.' + hawk.crypto.headerVersion + '.' + type + '\n' +
                         options.ts + '\n' +
                         options.nonce + '\n' +
                         (options.method || '').toUpperCase() + '\n' +
                         (options.resource || '') + '\n' +
                         options.host.toLowerCase() + '\n' +
                         options.port + '\n' +
                         (options.hash || '') + '\n';

        if (options.ext) {
            normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n');
        }

        normalized += '\n';

        if (options.app) {
            normalized += options.app + '\n' +
                          (options.dlg || '') + '\n';
        }

        return normalized;
    },

    calculatePayloadHash: function (payload, algorithm, contentType) {

        var hash = CryptoJS.algo[algorithm.toUpperCase()].create();
        hash.update('hawk.' + hawk.crypto.headerVersion + '.payload\n');
        hash.update(hawk.utils.parseContentType(contentType) + '\n');
        hash.update(payload);
        hash.update('\n');
        return hash.finalize().toString(CryptoJS.enc.Base64);
    },

    calculateTsMac: function (ts, credentials) {

        var hash = CryptoJS['Hmac' + credentials.algorithm.toUpperCase()]('hawk.' + hawk.crypto.headerVersion + '.ts\n' + ts + '\n', credentials.key);
        return hash.toString(CryptoJS.enc.Base64);
    }
};


// localStorage compatible interface

hawk.internals.LocalStorage = function () {

    this._cache = {};
    this.length = 0;

    this.getItem = function (key) {

        return this._cache.hasOwnProperty(key) ? String(this._cache[key]) : null;
    };

    this.setItem = function (key, value) {

        this._cache[key] = String(value);
        this.length = Object.keys(this._cache).length;
    };

    this.removeItem = function (key) {

        delete this._cache[key];
        this.length = Object.keys(this._cache).length;
    };

    this.clear = function () {

        this._cache = {};
        this.length = 0;
    };

    this.key = function (i) {

        return Object.keys(this._cache)[i || 0];
    };
};


hawk.utils = {

    storage: new hawk.internals.LocalStorage(),

    setStorage: function (storage) {

        var ntpOffset = hawk.utils.storage.getItem('hawk_ntp_offset');
        hawk.utils.storage = storage;
        if (ntpOffset) {
            hawk.utils.setNtpOffset(ntpOffset);
        }
    },

    setNtpOffset: function (offset) {

        try {
            hawk.utils.storage.setItem('hawk_ntp_offset', offset);
        }
        catch (err) {
            console.error('[hawk] could not write to storage.');
            console.error(err);
        }
    },

    getNtpOffset: function () {

        var offset = hawk.utils.storage.getItem('hawk_ntp_offset');
        if (!offset) {
            return 0;
        }

        return parseInt(offset, 10);
    },

    now: function (localtimeOffsetMsec) {

        return Math.floor(((new Date()).getTime() + (localtimeOffsetMsec || 0)) / 1000) + hawk.utils.getNtpOffset();
    },

    escapeHeaderAttribute: function (attribute) {

        return attribute.replace(/\\/g, '\\\\').replace(/\"/g, '\\"');
    },

    parseContentType: function (header) {

        if (!header) {
            return '';
        }

        return header.split(';')[0].replace(/^\s+|\s+$/g, '').toLowerCase();
    },

    parseAuthorizationHeader: function (header, keys) {

        if (!header) {
            return null;
        }

        var headerParts = header.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
        if (!headerParts) {
            return null;
        }

        var scheme = headerParts[1];
        if (scheme.toLowerCase() !== 'hawk') {
            return null;
        }

        var attributesString = headerParts[2];
        if (!attributesString) {
            return null;
        }

        var attributes = {};
        var verify = attributesString.replace(/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, function ($0, $1, $2) {

            // Check valid attribute names

            if (keys.indexOf($1) === -1) {
                return;
            }

            // Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9

            if ($2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) === null) {
                return;
            }

            // Check for duplicates

            if (attributes.hasOwnProperty($1)) {
                return;
            }

            attributes[$1] = $2;
            return '';
        });

        if (verify !== '') {
            return null;
        }

        return attributes;
    },

    randomString: function (size) {

        var randomSource = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        var len = randomSource.length;

        var result = [];
        for (var i = 0; i < size; ++i) {
            result[i] = randomSource[Math.floor(Math.random() * len)];
        }

        return result.join('');
    },

    uriRegex: /^([^:]+)\:\/\/(?:[^@]*@)?([^\/:]+)(?:\:(\d+))?([^#]*)(?:#.*)?$/,       // scheme://credentials@host:port/resource#fragment
    parseUri: function (input) {

        var parts = input.match(hawk.utils.uriRegex);
        if (!parts) {
            return { host: '', port: '', resource: '' };
        }

        var scheme = parts[1].toLowerCase();
        var uri = {
            host: parts[2],
            port: parts[3] || (scheme === 'http' ? '80' : (scheme === 'https' ? '443' : '')),
            resource: parts[4]
        };

        return uri;
    },

    base64urlEncode: function (value) {

        var wordArray = CryptoJS.enc.Utf8.parse(value);
        var encoded = CryptoJS.enc.Base64.stringify(wordArray);
        return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    }
};


// $lab:coverage:off$
/* eslint-disable */

// Based on: Crypto-JS v3.1.2
// Copyright (c) 2009-2013, Jeff Mott. All rights reserved.
// http://code.google.com/p/crypto-js/
// http://code.google.com/p/crypto-js/wiki/License

var CryptoJS = CryptoJS || function (h, r) { var k = {}, l = k.lib = {}, n = function () { }, f = l.Base = { extend: function (a) { n.prototype = this; var b = new n; a && b.mixIn(a); b.hasOwnProperty("init") || (b.init = function () { b.$super.init.apply(this, arguments) }); b.init.prototype = b; b.$super = this; return b }, create: function () { var a = this.extend(); a.init.apply(a, arguments); return a }, init: function () { }, mixIn: function (a) { for (var b in a) a.hasOwnProperty(b) && (this[b] = a[b]); a.hasOwnProperty("toString") && (this.toString = a.toString) }, clone: function () { return this.init.prototype.extend(this) } }, j = l.WordArray = f.extend({ init: function (a, b) { a = this.words = a || []; this.sigBytes = b != r ? b : 4 * a.length }, toString: function (a) { return (a || s).stringify(this) }, concat: function (a) { var b = this.words, d = a.words, c = this.sigBytes; a = a.sigBytes; this.clamp(); if (c % 4) for (var e = 0; e < a; e++) b[c + e >>> 2] |= (d[e >>> 2] >>> 24 - 8 * (e % 4) & 255) << 24 - 8 * ((c + e) % 4); else if (65535 < d.length) for (e = 0; e < a; e += 4) b[c + e >>> 2] = d[e >>> 2]; else b.push.apply(b, d); this.sigBytes += a; return this }, clamp: function () { var a = this.words, b = this.sigBytes; a[b >>> 2] &= 4294967295 << 32 - 8 * (b % 4); a.length = h.ceil(b / 4) }, clone: function () { var a = f.clone.call(this); a.words = this.words.slice(0); return a }, random: function (a) { for (var b = [], d = 0; d < a; d += 4) b.push(4294967296 * h.random() | 0); return new j.init(b, a) } }), m = k.enc = {}, s = m.Hex = { stringify: function (a) { var b = a.words; a = a.sigBytes; for (var d = [], c = 0; c < a; c++) { var e = b[c >>> 2] >>> 24 - 8 * (c % 4) & 255; d.push((e >>> 4).toString(16)); d.push((e & 15).toString(16)) } return d.join("") }, parse: function (a) { for (var b = a.length, d = [], c = 0; c < b; c += 2) d[c >>> 3] |= parseInt(a.substr(c, 2), 16) << 24 - 4 * (c % 8); return new j.init(d, b / 2) } }, p = m.Latin1 = { stringify: function (a) { var b = a.words; a = a.sigBytes; for (var d = [], c = 0; c < a; c++) d.push(String.fromCharCode(b[c >>> 2] >>> 24 - 8 * (c % 4) & 255)); return d.join("") }, parse: function (a) { for (var b = a.length, d = [], c = 0; c < b; c++) d[c >>> 2] |= (a.charCodeAt(c) & 255) << 24 - 8 * (c % 4); return new j.init(d, b) } }, t = m.Utf8 = { stringify: function (a) { try { return decodeURIComponent(escape(p.stringify(a))) } catch (b) { throw Error("Malformed UTF-8 data"); } }, parse: function (a) { return p.parse(unescape(encodeURIComponent(a))) } }, q = l.BufferedBlockAlgorithm = f.extend({ reset: function () { this._data = new j.init; this._nDataBytes = 0 }, _append: function (a) { "string" == typeof a && (a = t.parse(a)); this._data.concat(a); this._nDataBytes += a.sigBytes }, _process: function (a) { var b = this._data, d = b.words, c = b.sigBytes, e = this.blockSize, f = c / (4 * e), f = a ? h.ceil(f) : h.max((f | 0) - this._minBufferSize, 0); a = f * e; c = h.min(4 * a, c); if (a) { for (var g = 0; g < a; g += e) this._doProcessBlock(d, g); g = d.splice(0, a); b.sigBytes -= c } return new j.init(g, c) }, clone: function () { var a = f.clone.call(this); a._data = this._data.clone(); return a }, _minBufferSize: 0 }); l.Hasher = q.extend({ cfg: f.extend(), init: function (a) { this.cfg = this.cfg.extend(a); this.reset() }, reset: function () { q.reset.call(this); this._doReset() }, update: function (a) { this._append(a); this._process(); return this }, finalize: function (a) { a && this._append(a); return this._doFinalize() }, blockSize: 16, _createHelper: function (a) { return function (b, d) { return (new a.init(d)).finalize(b) } }, _createHmacHelper: function (a) { return function (b, d) { return (new u.HMAC.init(a, d)).finalize(b) } } }); var u = k.algo = {}; return k }(Math);
(function () { var k = CryptoJS, b = k.lib, m = b.WordArray, l = b.Hasher, d = [], b = k.algo.SHA1 = l.extend({ _doReset: function () { this._hash = new m.init([1732584193, 4023233417, 2562383102, 271733878, 3285377520]) }, _doProcessBlock: function (n, p) { for (var a = this._hash.words, e = a[0], f = a[1], h = a[2], j = a[3], b = a[4], c = 0; 80 > c; c++) { if (16 > c) d[c] = n[p + c] | 0; else { var g = d[c - 3] ^ d[c - 8] ^ d[c - 14] ^ d[c - 16]; d[c] = g << 1 | g >>> 31 } g = (e << 5 | e >>> 27) + b + d[c]; g = 20 > c ? g + ((f & h | ~f & j) + 1518500249) : 40 > c ? g + ((f ^ h ^ j) + 1859775393) : 60 > c ? g + ((f & h | f & j | h & j) - 1894007588) : g + ((f ^ h ^ j) - 899497514); b = j; j = h; h = f << 30 | f >>> 2; f = e; e = g } a[0] = a[0] + e | 0; a[1] = a[1] + f | 0; a[2] = a[2] + h | 0; a[3] = a[3] + j | 0; a[4] = a[4] + b | 0 }, _doFinalize: function () { var b = this._data, d = b.words, a = 8 * this._nDataBytes, e = 8 * b.sigBytes; d[e >>> 5] |= 128 << 24 - e % 32; d[(e + 64 >>> 9 << 4) + 14] = Math.floor(a / 4294967296); d[(e + 64 >>> 9 << 4) + 15] = a; b.sigBytes = 4 * d.length; this._process(); return this._hash }, clone: function () { var b = l.clone.call(this); b._hash = this._hash.clone(); return b } }); k.SHA1 = l._createHelper(b); k.HmacSHA1 = l._createHmacHelper(b) })();
(function (k) { for (var g = CryptoJS, h = g.lib, v = h.WordArray, j = h.Hasher, h = g.algo, s = [], t = [], u = function (q) { return 4294967296 * (q - (q | 0)) | 0 }, l = 2, b = 0; 64 > b;) { var d; a: { d = l; for (var w = k.sqrt(d), r = 2; r <= w; r++) if (!(d % r)) { d = !1; break a } d = !0 } d && (8 > b && (s[b] = u(k.pow(l, 0.5))), t[b] = u(k.pow(l, 1 / 3)), b++); l++ } var n = [], h = h.SHA256 = j.extend({ _doReset: function () { this._hash = new v.init(s.slice(0)) }, _doProcessBlock: function (q, h) { for (var a = this._hash.words, c = a[0], d = a[1], b = a[2], k = a[3], f = a[4], g = a[5], j = a[6], l = a[7], e = 0; 64 > e; e++) { if (16 > e) n[e] = q[h + e] | 0; else { var m = n[e - 15], p = n[e - 2]; n[e] = ((m << 25 | m >>> 7) ^ (m << 14 | m >>> 18) ^ m >>> 3) + n[e - 7] + ((p << 15 | p >>> 17) ^ (p << 13 | p >>> 19) ^ p >>> 10) + n[e - 16] } m = l + ((f << 26 | f >>> 6) ^ (f << 21 | f >>> 11) ^ (f << 7 | f >>> 25)) + (f & g ^ ~f & j) + t[e] + n[e]; p = ((c << 30 | c >>> 2) ^ (c << 19 | c >>> 13) ^ (c << 10 | c >>> 22)) + (c & d ^ c & b ^ d & b); l = j; j = g; g = f; f = k + m | 0; k = b; b = d; d = c; c = m + p | 0 } a[0] = a[0] + c | 0; a[1] = a[1] + d | 0; a[2] = a[2] + b | 0; a[3] = a[3] + k | 0; a[4] = a[4] + f | 0; a[5] = a[5] + g | 0; a[6] = a[6] + j | 0; a[7] = a[7] + l | 0 }, _doFinalize: function () { var d = this._data, b = d.words, a = 8 * this._nDataBytes, c = 8 * d.sigBytes; b[c >>> 5] |= 128 << 24 - c % 32; b[(c + 64 >>> 9 << 4) + 14] = k.floor(a / 4294967296); b[(c + 64 >>> 9 << 4) + 15] = a; d.sigBytes = 4 * b.length; this._process(); return this._hash }, clone: function () { var b = j.clone.call(this); b._hash = this._hash.clone(); return b } }); g.SHA256 = j._createHelper(h); g.HmacSHA256 = j._createHmacHelper(h) })(Math);
(function () { var c = CryptoJS, k = c.enc.Utf8; c.algo.HMAC = c.lib.Base.extend({ init: function (a, b) { a = this._hasher = new a.init; "string" == typeof b && (b = k.parse(b)); var c = a.blockSize, e = 4 * c; b.sigBytes > e && (b = a.finalize(b)); b.clamp(); for (var f = this._oKey = b.clone(), g = this._iKey = b.clone(), h = f.words, j = g.words, d = 0; d < c; d++) h[d] ^= 1549556828, j[d] ^= 909522486; f.sigBytes = g.sigBytes = e; this.reset() }, reset: function () { var a = this._hasher; a.reset(); a.update(this._iKey) }, update: function (a) { this._hasher.update(a); return this }, finalize: function (a) { var b = this._hasher; a = b.finalize(a); b.reset(); return b.finalize(this._oKey.clone().concat(a)) } }) })();
(function () { var h = CryptoJS, j = h.lib.WordArray; h.enc.Base64 = { stringify: function (b) { var e = b.words, f = b.sigBytes, c = this._map; b.clamp(); b = []; for (var a = 0; a < f; a += 3) for (var d = (e[a >>> 2] >>> 24 - 8 * (a % 4) & 255) << 16 | (e[a + 1 >>> 2] >>> 24 - 8 * ((a + 1) % 4) & 255) << 8 | e[a + 2 >>> 2] >>> 24 - 8 * ((a + 2) % 4) & 255, g = 0; 4 > g && a + 0.75 * g < f; g++) b.push(c.charAt(d >>> 6 * (3 - g) & 63)); if (e = c.charAt(64)) for (; b.length % 4;) b.push(e); return b.join("") }, parse: function (b) { var e = b.length, f = this._map, c = f.charAt(64); c && (c = b.indexOf(c), -1 != c && (e = c)); for (var c = [], a = 0, d = 0; d < e; d++) if (d % 4) { var g = f.indexOf(b.charAt(d - 1)) << 2 * (d % 4), h = f.indexOf(b.charAt(d)) >>> 6 - 2 * (d % 4); c[a >>> 2] |= (g | h) << 24 - 8 * (a % 4); a++ } return j.create(c, a) }, _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" } })();

hawk.crypto.internals = CryptoJS;


// Export if used as a module

if (typeof module !== 'undefined' && module.exports) {
    module.exports = hawk;
}

/* eslint-enable */
// $lab:coverage:on$

},{}],15:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],16:[function(require,module,exports){
(function (process){
/*!
 * Copyright 2013 Robert Katić
 * Released under the MIT license
 * https://github.com/rkatic/p/blob/master/LICENSE
 *
 * High-priority-tasks code-portion based on https://github.com/kriskowal/asap
 * Long-Stack-Support code-portion based on https://github.com/kriskowal/q
 */
;(function( factory ){
	// CommonJS
	if ( typeof module !== "undefined" && module && module.exports ) {
		module.exports = factory();

	// RequireJS
	} else if ( typeof define === "function" && define.amd ) {
		define( factory );

	// global
	} else {
		P = factory();
	}
})(function() {
	"use strict";

	var withStack = withStackThrowing,
		pStartingLine = captureLine(),
		pFileName,
		currentTrace = null;

	function withStackThrowing( error ) {
		if ( !error.stack ) {
			try {
				throw error;
			} catch ( e ) {}
		}
		return error;
	}

	if ( new Error().stack ) {
		withStack = function( error ) {
			return error;
		};
	}

	function getTrace() {
		var stack = withStack( new Error() ).stack;
		if ( !stack ) {
			return null;
		}

		var stacks = [ filterStackString( stack, 1 ) ];

		if ( currentTrace ) {
			stacks = stacks.concat( currentTrace );

			if ( stacks.length === 128 ) {
				stacks.pop();
			}
		}

		return stacks;
	}

	function getFileNameAndLineNumber( stackLine ) {
		var m =
			/at .+ \((.+):(\d+):(?:\d+)\)$/.exec( stackLine ) ||
			/at ([^ ]+):(\d+):(?:\d+)$/.exec( stackLine ) ||
			/@(.+):(\d+):(?:\d+)$/.exec( stackLine );

		return m ? { fileName: m[1], lineNumber: Number(m[2]) } : null;
	}

	function captureLine() {
		var stack = withStack( new Error() ).stack;
		if ( !stack ) {
			return 0;
		}

		var lines = stack.split("\n");
		var firstLine = lines[0].indexOf("@") > 0 ? lines[1] : lines[2];
		var pos = getFileNameAndLineNumber( firstLine );
		if ( !pos ) {
			return 0;
		}

		pFileName = pos.fileName;
		return pos.lineNumber;
	}

	function filterStackString( stack, ignoreFirstLines ) {
		var lines = stack.split("\n");
		var goodLines = [];

		for ( var i = ignoreFirstLines|0, l = lines.length; i < l; ++i ) {
			var line = lines[i];

			if ( line && !isNodeFrame(line) && !isInternalFrame(line) ) {
				goodLines.push( line );
			}
		}

		return goodLines.join("\n");
	}

	function isNodeFrame( stackLine ) {
		return stackLine.indexOf("(module.js:") !== -1 ||
			   stackLine.indexOf("(node.js:") !== -1;
	}

	function isInternalFrame( stackLine ) {
		var pos = getFileNameAndLineNumber( stackLine );
		return !!pos &&
			pos.fileName === pFileName &&
			pos.lineNumber >= pStartingLine &&
			pos.lineNumber <= pEndingLine;
	}

	var STACK_JUMP_SEPARATOR = "\nFrom previous event:\n";

	function makeStackTraceLong( error ) {
		if ( error instanceof Error ) {
			var stack = error.stack;

			if ( !stack ) {
				stack = withStack( error ).stack;

			} else if ( ~stack.indexOf(STACK_JUMP_SEPARATOR) ) {
				return;
			}

			if ( stack ) {
				error.stack = [ filterStackString( stack, 0 ) ]
					.concat( currentTrace || [] )
					.join(STACK_JUMP_SEPARATOR);
			}
		}
	}

	//__________________________________________________________________________

	var
		isNodeJS = ot(typeof process) && process != null &&
			({}).toString.call(process) === "[object process]",

		hasSetImmediate = typeof setImmediate === "function",

		gMutationObserver =
			ot(typeof MutationObserver) && MutationObserver ||
			ot(typeof WebKitMutationObserver) && WebKitMutationObserver,

		head = new TaskNode(),
		tail = head,
		flushing = false,
		nFreeTaskNodes = 0,

		requestFlush =
			isNodeJS ? requestFlushForNodeJS :
			gMutationObserver ? makeRequestCallFromMutationObserver( flush ) :
			makeRequestCallFromTimer( flush ),

		pendingErrors = [],
		requestErrorThrow = makeRequestCallFromTimer( throwFirstError ),

		handleError,

		domain,

		call = ot.call,
		apply = ot.apply;

	tail.next = head;

	function TaskNode() {
		this.f = null;
		this.a = null;
		this.b = null;
		this.next = null;
	}

	function ot( type ) {
		return type === "object" || type === "function";
	}

	function throwFirstError() {
		if ( pendingErrors.length ) {
			throw pendingErrors.shift();
		}
	}

	function flush() {
		while ( head !== tail ) {
			var h = head = head.next;

			if ( nFreeTaskNodes >= 1024 ) {
				tail.next = tail.next.next;
			} else {
				++nFreeTaskNodes;
			}

			var f = h.f;
			var a = h.a;
			var b = h.b;
			h.f = null;
			h.a = null;
			h.b = null;

			f( a, b );
		}

		flushing = false;
		currentTrace = null;
	}

	function schedule( f, a, b ) {
		var node = tail.next;

		if ( node === head ) {
			tail.next = node = new TaskNode();
			node.next = head;
		} else {
			--nFreeTaskNodes;
		}

		tail = node;

		node.f = f;
		node.a = a;
		node.b = b;

		if ( !flushing ) {
			flushing = true;
			requestFlush();
		}
	}

	function requestFlushForNodeJS() {
		var currentDomain = process.domain;

		if ( currentDomain ) {
			if ( !domain ) domain = (1,require)("domain");
			domain.active = process.domain = null;
		}

		if ( flushing && hasSetImmediate ) {
			setImmediate( flush );

		} else {
			process.nextTick( flush );
		}

		if ( currentDomain ) {
			domain.active = process.domain = currentDomain;
		}
	}

	function makeRequestCallFromMutationObserver( callback ) {
		var toggle = 1;
		var node = document.createTextNode("");
		var observer = new gMutationObserver( callback );
		observer.observe( node, {characterData: true} );

		return function() {
			toggle = -toggle;
			node.data = toggle;
		};
	}

	function makeRequestCallFromTimer( callback ) {
		return function() {
			var timeoutHandle = setTimeout( handleTimer, 0 );
			var intervalHandle = setInterval( handleTimer, 50 );

			function handleTimer() {
				clearTimeout( timeoutHandle );
				clearInterval( intervalHandle );
				callback();
			}
		};
	}

	if ( isNodeJS ) {
		handleError = function( e ) {
			currentTrace = null;
			requestFlush();
			throw e;
		};

	} else {
		handleError = function( e ) {
			pendingErrors.push( e );
			requestErrorThrow();
		}
	}

	//__________________________________________________________________________

	var FULFILLED = 1;
	var REJECTED = 2;

	var OP_CALL = -1;
	var OP_THEN = -2;
	var OP_MULTIPLE = -3;
	var OP_END = -4;

	var VOID = P(void 0);

	function DoneEb( e ) {
		if ( P.onerror ) {
			(1,P.onerror)( e );

		} else {
			throw e;
		}
	}

	function P( x ) {
		return x instanceof Promise ?
			x :
			Resolve( new Promise(), x );
	}

	P.longStackSupport = false;

	function Fulfill( p, value ) {
		if ( p._state > 0 ) {
			return;
		}

		p._state = FULFILLED;
		p._value = value;
		p._domain = null;

		HandleSettled( p );
	}

	function Reject( p, reason ) {
		if ( p._state > 0 ) {
			return;
		}

		if ( currentTrace ) {
			makeStackTraceLong( reason );
		}

		p._state = REJECTED;
		p._value = reason;

		if ( isNodeJS ) {
			p._domain = process.domain;
		}

		if ( p._op === OP_END ) {
			handleError( reason );

		} else {
			HandleSettled( p );
		}
	}

	function Propagate( parent, p ) {
		if ( p._state > 0 ) {
			return;
		}

		p._state = parent._state;
		p._value = parent._value;
		p._domain = parent._domain;

		HandleSettled( p );
	}

	function Resolve( p, x ) {
		if ( p._state > 0 ) {
			return p;
		}

		if ( x instanceof Promise ) {
			ResolveWithPromise( p, x );

		} else {
			var type = typeof x;

			if ( type === "object" && x !== null || type === "function" ) {
				ResolveWithObject( p, x )

			} else {
				Fulfill( p, x );
			}
		}

		return p;
	}

	function ResolveWithPromise( p, x ) {
		if ( x === p ) {
			Reject( p, new TypeError("You can't resolve a promise with itself") );

		} else if ( x._state > 0 ) {
			Propagate( x, p );

		} else {
			OnSettled( x, OP_THEN, p );
		}
	}

	function ResolveWithObject( p, x ) {
		var then = GetThen( p, x );

		if ( typeof then === "function" ) {
			TryResolver( resolverFor(p, false), then, x );

		} else {
			Fulfill( p, x );
		}
	}

	function GetThen( p, x ) {
		try {
			return x.then;

		} catch ( e ) {
			Reject( p, e );
			return null;
		}
	}

	function TryResolver( d, resolver, x ) {
		try {
			call.call( resolver, x, d.resolve, d.reject );

		} catch ( e ) {
			d.reject( e );
		}
	}

	function HandleSettled( p ) {
		if ( p._pending !== null ) {
			HandlePending( p, p._op, p._pending );
			p._pending = null;
		}
	}

	function HandlePending( p, op, pending ) {
		if ( op >= 0 ) {
			pending._cb( p, op );

		} else if ( op === OP_CALL ) {
			pending( p );

		} else if ( op === OP_THEN ) {
			schedule( Then, p, pending );

		} else {
			for ( var i = 0, l = pending.length; i < l; i += 2 ) {
				HandlePending( p, pending[i], pending[i + 1] );
			}
		}
	}

	function OnSettled( p, op, pending ) {
		if ( p._state > 0 ) {
			HandlePending( p, op, pending );

		} else if ( p._pending === null ) {
			p._pending = pending;
			p._op = op;

		} else if ( p._op === OP_MULTIPLE ) {
			p._pending.push( op, pending );

		} else {
			p._pending = [ p._op, p._pending, op, pending ];
			p._op = OP_MULTIPLE;
		}
	}

	function Then( parent, p ) {
		var cb = parent._state === FULFILLED ? p._cb : p._eb;
		p._cb = null;
		p._eb = null;

		if ( p._trace ) {
			currentTrace = p._trace;
			p._trace = null;
		}

		if ( cb === null ) {
			Propagate( parent, p );

		} else {
			HandleCallback( p, cb, parent._value, parent._domain || p._domain );
		}
	}

	function HandleCallback( p, cb, value, domain ) {
		if ( domain ) {
			if ( domain._disposed ) return;
			domain.enter();
		}

		try {
			value = cb( value );

		} catch ( e ) {
			Reject( p, e );
			p = null;
		}

		if ( p ) Resolve( p, value );
		if ( domain ) domain.exit();
	}

	function resolverFor( promise, nodelike ) {
		var trace = P.longStackSupport ? getTrace() : null;

		function resolve( error, y ) {
			if ( promise ) {
				var p = promise;
				promise = null;

				if ( trace ) {
					if ( currentTrace ) {
						trace = null;

					} else {
						currentTrace = trace;
					}
				}

				if ( error ) {
					Reject( p, nodelike ? error : y );

				} else {
					Resolve( p, y );
				}

				if ( trace ) {
					currentTrace = trace = null;
				}
			}
		}

		return nodelike ? resolve : {
			promise: promise,

			resolve: function( y ) {
				resolve( false, y );
			},

			reject: function( reason ) {
				resolve( true, reason );
			}
		};
	}

	P.defer = defer;
	function defer() {
		return resolverFor( new Promise(), false );
	}

	P.reject = reject;
	function reject( reason ) {
		var promise = new Promise();
		Reject( promise, reason );
		return promise;
	}

	function Promise() {
		this._state = 0;
		this._value = void 0;
		this._domain = null;
		this._cb = null;
		this._eb = null;
		this._op = 0;
		this._pending = null;
		this._trace = null;
	}

	Promise.prototype.then = function( onFulfilled, onRejected ) {
		var promise = new Promise();

		promise._cb = typeof onFulfilled === "function" ? onFulfilled : null;
		promise._eb = typeof onRejected === "function" ? onRejected : null;

		if ( P.longStackSupport ) {
			promise._trace = getTrace();
		}

		if ( isNodeJS ) {
			promise._domain = process.domain;
		}

		if ( this._state > 0 ) {
			schedule( Then, this, promise );

		} else {
			OnSettled( this, OP_THEN, promise );
		}

		return promise;
	};

	Promise.prototype.done = function( cb, eb ) {
		var p = this;

		if ( cb || eb ) {
			p = p.then( cb, eb );
		}

		p.then( null, DoneEb )._op = OP_END;
	};

	Promise.prototype.fail = function( eb ) {
		return this.then( null, eb );
	};

	Promise.prototype.fin = function( finback ) {
		var self = this;

		function fb() {
			return finback();
		}

		return self.then( fb, fb ).then(function() {
			return self;
		});
	};

	Promise.prototype.spread = function( cb, eb ) {
		return this.then( all ).then(function( args ) {
			return apply.call( cb, void 0, args );
		}, eb);
	};

	Promise.prototype.timeout = function( ms, msg ) {
		var promise = new Promise();

		if ( this._state > 0 ) {
			Propagate( this, promise );

		} else {
			var timedout = false;
			var trace = P.longStackSupport ? getTrace() : null;

			var timeoutId = setTimeout(function() {
				timedout = true;
				currentTrace = trace;
				Reject( promise, new Error(msg || "Timed out after " + ms + " ms") );
				currentTrace = null;
			}, ms);

			OnSettled(this, OP_CALL, function( p ) {
				if ( !timedout ) {
					schedule( Propagate, p, promise );
					clearTimeout( timeoutId );
				}
			});
		}

		return promise;
	};

	Promise.prototype.delay = function( ms ) {
		var promise = new Promise();

		OnSettled(this, OP_CALL, function( p ) {
			if ( p._state === FULFILLED ) {
				setTimeout(function() {
					Propagate( p, promise );
				}, ms);

			} else {
				schedule( Propagate, p, promise );
			}
		});

		return promise;
	};

	Promise.prototype.all = function() {
		return this.then( all );
	};

	Promise.prototype.allSettled = function() {
		return this.then( allSettled );
	};

	Promise.prototype.inspect = function() {
		switch ( this._state ) {
			case FULFILLED: return { state: "fulfilled", value: this._value };
			case REJECTED:  return { state: "rejected", reason: this._value };
			default:		return { state: "pending" };
		}
	};

	Promise.prototype.nodeify = function( nodeback ) {
		if ( nodeback ) {
			this.done(function( value ) {
				nodeback( null, value );
			}, nodeback);
			return void 0;

		} else {
			return this;
		}
	};

	function _allSettled_cb( p, i ) {
		this._value[ i ] = p.inspect();
		if ( ++this._state === 0 ) {
			if ( this._pending === null ) {
				this._state = FULFILLED;
			} else {
				schedule( Fulfill, this, this._value );
			}
		}
	}

	function _all_cb( p, i ) {
		if ( this._state < 0 ) {
			if ( p._state === REJECTED ) {
				this._state = 0;
				if ( this._pending === null ) {
					Propagate( p, this );
				} else {
					schedule( Propagate, p, this );
				}

			} else {
				this._value[ i ] = p._value;
				if ( ++this._state === 0 ) {
					if ( this._pending === null ) {
						this._state = FULFILLED;
					} else {
						schedule( Fulfill, this, this._value );
					}
				}
			}
		}
	}

	var nextIsAllSettled = false;

	P.all = all;
	function all( input ) {
		var promise = new Promise();
		promise._cb = nextIsAllSettled ? _allSettled_cb : _all_cb;
		nextIsAllSettled = false;

		var len = input.length|0;

		promise._state = len ? -len : FULFILLED;
		promise._value = new Array( len );

		for ( var i = 0; i < len && promise._state < 0; ++i ) {
			OnSettled( P(input[i]), i, promise );
		}

		return promise;
	}

	P.allSettled = allSettled;
	function allSettled( input ) {
		nextIsAllSettled = true;
		return all( input );
	}

	P.spread = spread;
	function spread( values, cb, eb ) {
		return all( values ).then(function( args ) {
			return apply.call( cb, void 0, args );
		}, eb);
	}

	P.promised = promised;
	function promised( f ) {
		function onFulfilled( thisAndArgs ) {
			return call.apply( f, thisAndArgs );
		}

		return function() {
			var len = arguments.length;
			var thisAndArgs = new Array( len + 1 );
			thisAndArgs[0] = this;
			for ( var i = 0; i < len; ++i ) {
				thisAndArgs[ i + 1 ] = arguments[ i ];
			}
			return all( thisAndArgs ).then( onFulfilled );
		};
	}

	P.denodeify = denodeify;
	function denodeify( f ) {
		return function() {
			var promise = new Promise();

			var i = arguments.length;
			var args = new Array( i + 1 );
			args[i] = resolverFor( promise, true );
			while ( i-- ) {
				args[i] = arguments[i];
			}

			TryApply( promise, f, this, args );

			return promise;
		};
	}

	function TryApply( p, f, that, args ) {
		try {
			apply.call( f, that, args );

		} catch ( e ) {
			Reject( p, e );
		}
	}

	P.onerror = null;

	P.nextTick = function nextTick( task ) {
		// We don't use .done to avoid P.onerror.
		VOID.then(function() {
			task.call();
		})._op = OP_END;
	};

	var pEndingLine = captureLine();

	return P;
});

}).call(this,require('_process'))
},{"_process":17}],17:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = setTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    clearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        setTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],18:[function(require,module,exports){
/**
sprintf() for JavaScript 0.7-beta1
http://www.diveintojavascript.com/projects/javascript-sprintf

Copyright (c) Alexandru Marasteanu <alexaholic [at) gmail (dot] com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of sprintf() for JavaScript nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Alexandru Marasteanu BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Changelog:
2010.11.07 - 0.7-beta1-node
  - converted it to a node.js compatible module

2010.09.06 - 0.7-beta1
  - features: vsprintf, support for named placeholders
  - enhancements: format cache, reduced global namespace pollution

2010.05.22 - 0.6:
 - reverted to 0.4 and fixed the bug regarding the sign of the number 0
 Note:
 Thanks to Raphael Pigulla <raph (at] n3rd [dot) org> (http://www.n3rd.org/)
 who warned me about a bug in 0.5, I discovered that the last update was
 a regress. I appologize for that.

2010.05.09 - 0.5:
 - bug fix: 0 is now preceeded with a + sign
 - bug fix: the sign was not at the right position on padded results (Kamal Abdali)
 - switched from GPL to BSD license

2007.10.21 - 0.4:
 - unit test and patch (David Baird)

2007.09.17 - 0.3:
 - bug fix: no longer throws exception on empty paramenters (Hans Pufal)

2007.09.11 - 0.2:
 - feature: added argument swapping

2007.04.03 - 0.1:
 - initial release
**/

var sprintf = (function() {
	function get_type(variable) {
		return Object.prototype.toString.call(variable).slice(8, -1).toLowerCase();
	}
	function str_repeat(input, multiplier) {
		for (var output = []; multiplier > 0; output[--multiplier] = input) {/* do nothing */}
		return output.join('');
	}

	var str_format = function() {
		if (!str_format.cache.hasOwnProperty(arguments[0])) {
			str_format.cache[arguments[0]] = str_format.parse(arguments[0]);
		}
		return str_format.format.call(null, str_format.cache[arguments[0]], arguments);
	};

	// convert object to simple one line string without indentation or
	// newlines. Note that this implementation does not print array
	// values to their actual place for sparse arrays. 
	//
	// For example sparse array like this
	//    l = []
	//    l[4] = 1
	// Would be printed as "[1]" instead of "[, , , , 1]"
	// 
	// If argument 'seen' is not null and array the function will check for 
	// circular object references from argument.
	str_format.object_stringify = function(obj, depth, maxdepth, seen) {
		var str = '';
		if (obj != null) {
			switch( typeof(obj) ) {
			case 'function': 
				return '[Function' + (obj.name ? ': '+obj.name : '') + ']';
			    break;
			case 'object':
				if ( obj instanceof Error) { return '[' + obj.toString() + ']' };
				if (depth >= maxdepth) return '[Object]'
				if (seen) {
					// add object to seen list
					seen = seen.slice(0)
					seen.push(obj);
				}
				if (obj.length != null) { //array
					str += '[';
					var arr = []
					for (var i in obj) {
						if (seen && seen.indexOf(obj[i]) >= 0) arr.push('[Circular]');
						else arr.push(str_format.object_stringify(obj[i], depth+1, maxdepth, seen));
					}
					str += arr.join(', ') + ']';
				} else if ('getMonth' in obj) { // date
					return 'Date(' + obj + ')';
				} else { // object
					str += '{';
					var arr = []
					for (var k in obj) { 
						if(obj.hasOwnProperty(k)) {
							if (seen && seen.indexOf(obj[k]) >= 0) arr.push(k + ': [Circular]');
							else arr.push(k +': ' +str_format.object_stringify(obj[k], depth+1, maxdepth, seen)); 
						}
					}
					str += arr.join(', ') + '}';
				}
				return str;
				break;
			case 'string':				
				return '"' + obj + '"';
				break
			}
		}
		return '' + obj;
	}

	str_format.format = function(parse_tree, argv) {
		var cursor = 1, tree_length = parse_tree.length, node_type = '', arg, output = [], i, k, match, pad, pad_character, pad_length;
		for (i = 0; i < tree_length; i++) {
			node_type = get_type(parse_tree[i]);
			if (node_type === 'string') {
				output.push(parse_tree[i]);
			}
			else if (node_type === 'array') {
				match = parse_tree[i]; // convenience purposes only
				if (match[2]) { // keyword argument
					arg = argv[cursor];
					for (k = 0; k < match[2].length; k++) {
						if (!arg.hasOwnProperty(match[2][k])) {
							throw new Error(sprintf('[sprintf] property "%s" does not exist', match[2][k]));
						}
						arg = arg[match[2][k]];
					}
				}
				else if (match[1]) { // positional argument (explicit)
					arg = argv[match[1]];
				}
				else { // positional argument (implicit)
					arg = argv[cursor++];
				}

				if (/[^sO]/.test(match[8]) && (get_type(arg) != 'number')) {
					throw new Error(sprintf('[sprintf] expecting number but found %s "' + arg + '"', get_type(arg)));
				}
				switch (match[8]) {
					case 'b': arg = arg.toString(2); break;
					case 'c': arg = String.fromCharCode(arg); break;
					case 'd': arg = parseInt(arg, 10); break;
					case 'e': arg = match[7] ? arg.toExponential(match[7]) : arg.toExponential(); break;
					case 'f': arg = match[7] ? parseFloat(arg).toFixed(match[7]) : parseFloat(arg); break;
				    case 'O': arg = str_format.object_stringify(arg, 0, parseInt(match[7]) || 5); break;
					case 'o': arg = arg.toString(8); break;
					case 's': arg = ((arg = String(arg)) && match[7] ? arg.substring(0, match[7]) : arg); break;
					case 'u': arg = Math.abs(arg); break;
					case 'x': arg = arg.toString(16); break;
					case 'X': arg = arg.toString(16).toUpperCase(); break;
				}
				arg = (/[def]/.test(match[8]) && match[3] && arg >= 0 ? '+'+ arg : arg);
				pad_character = match[4] ? match[4] == '0' ? '0' : match[4].charAt(1) : ' ';
				pad_length = match[6] - String(arg).length;
				pad = match[6] ? str_repeat(pad_character, pad_length) : '';
				output.push(match[5] ? arg + pad : pad + arg);
			}
		}
		return output.join('');
	};

	str_format.cache = {};

	str_format.parse = function(fmt) {
		var _fmt = fmt, match = [], parse_tree = [], arg_names = 0;
		while (_fmt) {
			if ((match = /^[^\x25]+/.exec(_fmt)) !== null) {
				parse_tree.push(match[0]);
			}
			else if ((match = /^\x25{2}/.exec(_fmt)) !== null) {
				parse_tree.push('%');
			}
			else if ((match = /^\x25(?:([1-9]\d*)\$|\(([^\)]+)\))?(\+)?(0|'[^$])?(-)?(\d+)?(?:\.(\d+))?([b-fosOuxX])/.exec(_fmt)) !== null) {
				if (match[2]) {
					arg_names |= 1;
					var field_list = [], replacement_field = match[2], field_match = [];
					if ((field_match = /^([a-z_][a-z_\d]*)/i.exec(replacement_field)) !== null) {
						field_list.push(field_match[1]);
						while ((replacement_field = replacement_field.substring(field_match[0].length)) !== '') {
							if ((field_match = /^\.([a-z_][a-z_\d]*)/i.exec(replacement_field)) !== null) {
								field_list.push(field_match[1]);
							}
							else if ((field_match = /^\[(\d+)\]/.exec(replacement_field)) !== null) {
								field_list.push(field_match[1]);
							}
							else {
								throw new Error('[sprintf] ' + replacement_field);
							}
						}
					}
					else {
                        throw new Error('[sprintf] ' + replacement_field);
					}
					match[2] = field_list;
				}
				else {
					arg_names |= 2;
				}
				if (arg_names === 3) {
					throw new Error('[sprintf] mixing positional and named placeholders is not (yet) supported');
				}
				parse_tree.push(match);
			}
			else {
				throw new Error('[sprintf] ' + _fmt);
			}
			_fmt = _fmt.substring(match[0].length);
		}
		return parse_tree;
	};

	return str_format;
})();

var vsprintf = function(fmt, argv) {
	var argvClone = argv.slice();
	argvClone.unshift(fmt);
	return sprintf.apply(null, argvClone);
};

module.exports = sprintf;
sprintf.sprintf = sprintf;
sprintf.vsprintf = vsprintf;

},{}],19:[function(require,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],20:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./support/isBuffer":19,"_process":17,"inherits":15}],21:[function(require,module,exports){
/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave helper objects
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

// Export sub-modules


exports.account = {};
exports.account.fxa = require('./lib/account/fxa');
exports.account.legacy = require('./lib/account/legacy');

exports.client = require('./lib/weave-client');
exports.crypto = require('./lib/weave-crypto');
exports.storage = require('./lib/weave-storage');
exports.util = require('./lib/weave-util');
exports.error = require('./lib/weave-error');

module.exports = exports;

},{"./lib/account/fxa":1,"./lib/account/legacy":2,"./lib/weave-client":3,"./lib/weave-crypto":4,"./lib/weave-error":5,"./lib/weave-storage":7,"./lib/weave-util":8}]},{},[21])(21)
});