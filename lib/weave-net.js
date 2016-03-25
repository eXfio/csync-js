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

  setAuthProvider: function(provider) {
    this.authProvider = provider;
  },

  asyncGet: function(url, timeout, headers) {
    weave.util.Log.debug("HttpClient.asyncGet()");

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
