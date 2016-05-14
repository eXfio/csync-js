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
