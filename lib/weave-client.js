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

    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

	var wbo = this.storageClient.get(collection, id);
    
    if (decrypt) {
	  wbo = this.cryptoClient.decryptWeaveBasicObject(wbo, collection);
    }
    return wbo;
  },

  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, decrypt) {
    weave.util.Log.debug("weave.client.WeaveClient.getCollection()");

    //handle defaults
    decrypt = (typeof decrypt !== 'undefined' ? decrypt : true);

	var wbos = this.storageClient.getCollection(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format);

    if (decrypt) {
      var decWbos = [];
      for (var i = 0; i < wbos.length; i++) {
	    decWbos.push(this.cryptoClient.decryptWeaveBasicObject(wbos[i], collection));
      }
      wbos = decWbos;
    }
    return wbos;
  }

};

module.exports = baseClient;

