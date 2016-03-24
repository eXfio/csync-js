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
    weave.util.Log.debug("storage.WeaveBasicObject.getPayloadAsJSONObject()");
    return JSON.parse(this.payload);
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
	var response = this.httpClient.get(url, 2000);
    var jsonObject = JSON.parse(response);

    var wbo        = new storage.WeaveBasicObject();
	wbo.id         = jsonObject.id
	wbo.modified   = jsonObject.modified;
	wbo.sortindex  = jsonObject.sortindex;
	wbo.payload    = jsonObject.payload;
	wbo.ttl        = jsonObject.ttl;

    return wbo;
  },

  buildStorageUri: function(path) {
    return URI("storage/" + path).absoluteTo(this.storageURL).toString();
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

	var response = this.httpClient.get(url, 2000);
    var ids = JSON.parse(response);

    return ids;
  },
  
  getCollection: function(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format) {
    weave.util.Log.debug("StorageClient.getCollection()");

	var url = this.buildCollectionUri(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format, true);

	var response = this.httpClient.get(url, 2000);

    var jsonArray = JSON.parse(response);

    var wbos = [];
    for (var i = 0; i < jsonArray.length; i++) {
      var jsonObject = jsonArray[i];
      var wbo        = new storage.WeaveBasicObject();
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
