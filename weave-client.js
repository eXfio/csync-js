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
var URI = require('URIjs');

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
  
  decryptWeaveBasicObject: function(encWbo, collection) {
	if ( !isEncrypted(wbo) ) {
	  throw new weave.WeaveError("Weave Basic Object already decrypted");
	}
    
    var decWbo = new weave.client.WeaveBasicObject();
    
	decWbo.id         = encWbo.id
	decWbo.modified   = encWbo.modified;
	decWbo.sortindex  = encWbo.sortindex;
	decWbo.payload    = decrypt(encWbo.payload, collection);
	decWbo.ttl        = encWbo.ttl;
    
    return decWbo;
  },
  
  decrypt: function(payload, collection) {
    
    var keyPair = new weave.crypto.WeaveKeyPair();
    
    if ( collection === null ) {
      Weave.Log.info("Decrypting data record using sync key");
      
      try {
        keyPair = getPrivateKeyPair();
        } catch(e){
          throw new weave.WeaveError(e.message);
        }
      
    } else {
      Weave.Log.info(sprintf("Decrypting data record using bulk key %s", collection));
      
      keyPair = getBulkKeyPair(collection);
    }
    
    cipher = new weave.crypto.PayloadCipher();
    
    return cipher.decrypt(payload, keyPair);
  },
    
  /* asynchronous 
  function get(collection, id, decrypt, callback) {
    if (decrypt) {
	  this.storageClient.get(collection, id, function(wbo) {callback(this.decryptWeaveBasicObject(wbo, collection));});
    } else {
	  this.storageClient.get(collection, id, callback);
    }
  }
  */

  get: function(collection, id, decrypt) {
    weave.Log.debug("weave.client.WeaveClient.get()");

	var wbo = this.storageClient.get(collection, id);
    
    weave.Log.debug(util.inspect(wbo));

    if (decrypt) {
	  wbo = this.decryptWeaveBasicObject(wbo, collection);
    }
    return wbo;
  },

  getCollection: function(collection, decrypt) {
    weave.Log.debug("weave.client.WeaveClient.getCollection()");

	var wbos = this.storageClient.getCollection(collection, null, null, null, null, null, null, null, null, null);

    weave.Log.debug(util.inspect(wbos));
    
    if (decrypt) {
      var decWbos = [];
      for (wbo in wbos) {
	    decWbos.append(this.decryptWeaveBasicObject(wbo, collection));
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

  /* asynchronous
  function get(collection, id, callback) {
	weave.Log.debug("get()");
	getPath(collection + "/" + id, callback);
  }

  function getPath(path, callback) {
	weave.Log.debug("getPath()");

    var location = URI(sprintf("1.1/%s/storage/%s", this.user, path)).relativeTo(this.storageURL);
    
    weave.util.Net.get(location, 2000, this.processWeavePayload, callback);
  }
	

  function processWeavePayload(callback) {
	//parse content to extract JSON encoded WeaveBasicObject

    var jsonObject = JSON.parse(this.responseText);

    var wbo = new weave.client.WeaveBasicObject();

	wbo.id         = jsonObject.id
	wbo.modified   = jsonObject.modified;
	wbo.sortindex  = jsonObject.sortindex;
	wbo.payload    = jsonObject.payload;
	wbo.ttl        = jsonObject.ttl;

    callback(wbo);
  }
  */

  get: function(collection, id) {
	weave.Log.debug("get()");
	return getPath(collection + "/" + id);
  },

  getPath: function(path) {
	weave.Log.debug("getPath()");

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

    weave.Log.debug("url: " + url);

	var response = weave.net.Http.get(url, 2000);
    var ids = JSON.parse(response);

    return ids;
  },
  
  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format) {
    weave.Log.debug("weave.client.WeaveStorageApi.getCollection()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, true);

    weave.Log.debug("url: " + url);
    
	var response = weave.net.Http.get(url, 2000);
    var wbos = JSON.parse(response);

    return wbos;
  }
  
};
