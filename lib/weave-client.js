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

