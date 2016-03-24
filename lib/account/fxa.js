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
var FxAccountClient = require('fxa-js-client');
var xhr = require('xhr2');
var P   = require('p-promise');
var jwcrypto = require("browserid-crypto");
require("browserid-crypto/lib/algs/ds");
var URI = require('URIjs');
var sprintf = require('sprintf');
var forge = require('node-forge');

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

  this.accountServer = null;
  this.tokenServer   = null
  this.user          = null;
  this.password      = null;

  this.fxaClient            = null;
  this.fxaSession           = null;
  this.browserIdCertificate = null;
  this.syncToken            = null;
  this.kB                   = null;
  this.keyPair              = null;
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
    weave.util.Log.debug("weave.account.FxAccount.init()");
    
    this.accountServer = params.accountServer;
    this.tokenServer   = params.tokenServer;
	this.user          = params.user;
	this.password      = params.password;

    this.fxaClient            = new FxAccountClient(this.accountServer);
	this.fxaSession           = null;
	this.browserIdCertificate = null;
	this.syncToken            = null;
	this.kB                   = null;
	this.keyPair              = null;

    var self = this;
    
	return this.getSyncAuthToken()
      .then(
        function() {
          return self.getMasterKeyPair();
        }
      )
      .then(
        function() {
          return P(true);
        },
        function(error) {
          weave.util.Log.error("Couldn't initialise FxA account - " + error);
          return P.reject(error);
        }
      );
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
  getSyncAuthToken: function(audience, clearCache) {
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
    if ( clearCache === undefined ) {
      clearCache = false;
    }
    
	if ( clearCache ) {
	  this.syncToken = null;
	  this.fxaCertificate = null;
	}

	if ( this.syncToken !== null ) {
	  return P(this.syncToken);
	} else {
      
	  //We don't have a sync token so lets get one

      //gey keys
	  return this.getKeys()
        .then(
          function() {
	        //Get a signed certificate
	        return self.getCertificate()
          }
        )
        .then(
          function() {
            //Build assertion
            return self.buildAssertion(self.browserIdCertificate.keyPair, self.browserIdCertificate.certificate, audience);
          }
        )
        .then(
          function(assertion) {
            var clientState = self.deriveClientState();
            
	        //Request sync token
	        return self.getTokenFromBrowserIDAssertion(assertion, clientState);
          }
        )
        .then(
	      function(token) {
            weave.util.Log.debug("Sync token: " + JSON.stringify(token));
            
            self.syncToken = token;
	        return P(token);
          }
        )
        .fail(
          function(error) {
            weave.util.Log.error("Couldn't get sync token - " + error);
            return P.reject(error);
          }
        );
    }
    
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
    
    return this.initSession()
      .then(
        function() {
	      return self.fxaClient.accountKeys(self.fxaSession.keyFetchToken, self.fxaSession.unwrapBKey);
        }
      )
      .then(
        function(fxaKeys) {
          weave.util.Log.debug(sprintf("kA: %s, kB: %s", fxaKeys.kA, fxaKeys.kB));
          self.kB = forge.util.createBuffer(weave.util.Hex.decode(fxaKeys.kB));
          return P(fxaKeys);
        },
        function(error) {
	      weave.util.Log.error("Couldn't get FxA keys - " + error);
          return R.reject(error);
	    }
      );
  },
  
  getCertificate: function() {
	weave.util.Log.debug("getCertificate()");

	var self = this;

    var browserIdKeyPair = null;
    
	//Mozilla Android app used duration of 12 * 60 * 60 * 1000
	//long certificateDuration = 5 * 60 * 1000; //5minutes
	var certificateDuration = 12 * 60 * 60 * 1000; //12 hours
    
    return this.initSession()
      .then(
        function() {
          //Generate BrowserID KeyPair
	      return self.generateBrowserIdKeyPair();
        } 
      )
      .then(
        function(keyPair) {
          browserIdKeyPair = keyPair;          
	      return self.fxaClient.certificateSign(self.fxaSession.sessionToken, browserIdKeyPair.publicKey.serialize(), certificateDuration);
        }
	  ).then(
        function(certificate) {
          self.browserIdCertificate = {
            keyPair: browserIdKeyPair,
            certificate: certificate.cert
          };
          return P(self.browserIdCertificate);
        }
      )
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

    return httpClient.asyncGet(this.tokenServer, 2000, headers)
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
	weave.util.Log.debug("weave.account.fxa.getMasterKeyPair()");

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
