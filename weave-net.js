//nodejs includes
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var util = require('util');

//npm includes
var sprintf = require('sprintf');

//app includes
var weave = require('./weave-include');

weave.net = {};

weave.net.Http = (function() {
  
  var credentials = null;

  return {
    setCredentials: function(auth) {
      weave.util.Log.debug("weave.net.Http.setCredentials()");

      credentials = auth;
    },

    asyncGet: function(url, timeout) {
      var args = arguments;
      var xhr = new XMLHttpRequest();
      
      xhr.ontimeout = function () {
        throw new weave.WeaveError("Http request for " + url + " timed out.");
      };
      
      xhr.onload = function() {
        if (xhr.readyState !== 4) {
          return;
        }
        
        if (xhr.status !== 200) {
          throw new weave.WeaveError("Http request for " + url + " failed. " + xhr.status + " - " + xhr.statusText);
        }
        
        callback.apply(xhr, args);
      };
      
      xhr.open("GET", url, true);
      xhr.timeout = timeout;

      if ( credentials !== null ) {
		var auth = "Basic " + weave.util.Base64.encode(credentials.username + ":" + credentials.password);
        xhr.setRequestHeader("Authorization", auth);
      }

      xhr.send(null);
    },
    
    get: function(url, timeout) {
      weave.util.Log.debug("weave.net.Http.get()");

      var xhr = new XMLHttpRequest();
      
      xhr.open('GET', url, false);  // synchronous request
      xhr.timeout = timeout;

      if ( credentials !== null ) {
		var auth = "Basic " + weave.util.Base64.encode(credentials.username + ":" + credentials.password);
        xhr.setRequestHeader("Authorization", auth);
      }

      xhr.send(null);
      
      if (xhr.status != 200) {
        throw new weave.WeaveError("Http request failed - " + xhr.status + " - " + xhr.statusText);
      }
      
	  return xhr.responseText;
    }    
  };

}());
