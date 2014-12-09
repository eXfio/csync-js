//nodejs includes
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;

//npm includes
var sprintf = require('sprintf');

//app includes
var weave = require('./weave-include');

weave.net = {};

weave.net.Http = (function() {

  return {
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
      xhr.send(null);
    },
    
    get: function(url, timeout) {

      var xhr = new XMLHttpRequest();
      
      xhr.open('GET', url, false);  // synchronous request
      xhr.timeout = timeout;
      xhr.send(null);
      
      if (xhr.status != 200) {
        throw new weave.WeaveError("Http request failed - " + xhr.status + " - " + xhr.statusText);
      }
      
	  return xhr.responseText;
    }    
  };

}());
