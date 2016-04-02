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

  get: function(collection, id, decrypt) {
    weave.util.Log.debug("weave.client.WeaveClient.get()");

    var self = this;
    
    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

    return this.storageClient.get(collection, id)
      .then(function(wbo) {
        if (decrypt) {
	      return self.cryptoClient.decryptWeaveBasicObject(wbo, collection)
            .then(function(wbo) {
              return P(wbo);
            });
        }
        return P(wbo);
      })
      .fail(function(error) {
        weave.util.Log.error("Couldn't get weave collection - " + error);
        return P.reject(error);
      });
  },

  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, decrypt) {
    weave.util.Log.debug("weave.client.WeaveClient.getCollection()");

    var self = this;
    
    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

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
        weave.util.Log.error("Couldn't get weave collection - " + error);
        return P.reject(error);
      });
  },

  put: function(collection, id, wbo, encrypt) {
    weave.util.Log.debug("weave.client.WeaveClient.put()");
    throw new weave.error.WeaveError("Put not yet implemented");
  },

  delete: function(collection, id) {
    weave.util.Log.debug("weave.client.WeaveClient.delete()");
    throw new weave.error.WeaveError("Delete not yet implemented");
  },

  deleteCollection: function(collection) {
    weave.util.Log.debug("weave.client.WeaveClient.deleteCollection()");
    throw new weave.error.WeaveError("Delete not yet implemented");
  },

};

module.exports = baseClient;

