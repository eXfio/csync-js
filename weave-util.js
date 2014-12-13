//npm includes
var sprintf = require('sprintf').sprintf;
var forge   = require('node-forge');

//app includes
var weave = require('./weave-include');

weave.util = {};

weave.util.Log = (function() {

  var log = function(level, msg) {
    forge.log.logMessage({level: level, message: msg});
  };

  return {
    debug: function(msg) { log("debug", msg); },
    info: function(msg) { log("info", msg); },
    warn: function(msg) { log("warning", msg); },
    error: function(msg) { log("error", msg); }
  };
})();

weave.util.Base64 = (function() {
  
  return {
    decode: function(encoded) { 
      return forge.util.decode64(encoded)
    },

    encode: function(bin) {
      return forge.util.encode64(bin)
    }

  };
 
})();

weave.util.Base32 = (function() {

  return {
    decode: function(encoded) { 

      /// <summary>Decodes a base32 encoded string into a Uin8Array, note padding is not supported</summary>
      /// <param name="encoded" type="String">The base32 encoded string to be decoded</param>
      /// <returns type="Uint8Array">The Unit8Array representation of the data that was encoded in encoded</returns>
      if (!encoded && encoded !== "") {
        throw "encoded cannot be null or undefined";
      }

      if (encoded.length * 5 % 8 !== 0) {
        throw "encoded is not of the proper length. Please verify padding.";
      }

      encoded = encoded.toLowerCase();
      var alphabet = "abcdefghijklmnopqrstuvwxyz234567";
      var returnArray = new Array(encoded.length * 5 / 8);

      var currentByte = 0;
      var bitsRemaining = 8;
      var mask = 0;
      var arrayIndex = 0;

      for (var count = 0; count < encoded.length; count++) {
        var currentIndexValue = alphabet.indexOf(encoded[count]);
        if (-1 === currentIndexValue) {
          if ("=" === encoded[count]) {
            var paddingCount = 0;
            for (count = count; count < encoded.length; count++) {
              if ("=" !== encoded[count]) {
                throw "Invalid '=' in encoded string";
              } else {
                paddingCount++;
              }
            }

            switch (paddingCount) {
            case 6:
              returnArray = returnArray.slice(0, returnArray.length - 4);
              break;
            case 4:
              returnArray = returnArray.slice(0, returnArray.length - 3);
              break;
            case 3:
              returnArray = returnArray.slice(0, returnArray.length - 2);
              break;
            case 1:
              returnArray = returnArray.slice(0, returnArray.length - 1);
              break;
            default:
              throw "Incorrect padding";
            }
          } else {
            throw "Encoded string contains invalid characters or invalid padding.";
          }
        } else {
          if (bitsRemaining > 5) {
            mask = currentIndexValue << (bitsRemaining - 5);
            currentByte = currentByte | mask;
            bitsRemaining -= 5;
          } else {
            mask = currentIndexValue >> (5 - bitsRemaining);
            currentByte = currentByte | mask;
            returnArray[arrayIndex++] = currentByte;
            currentByte = currentIndexValue << (3 + bitsRemaining);
            bitsRemaining += 3;
          }
        }
      }

      var retval = new Uint8Array(returnArray);
      return weave.util.BinUtils.uint8ToString(retval);
    },

    encode: function(bin) {
      throw new weave.WeaveError("Base 32 encode not supported");
    }

  };

})();

weave.util.Hex = (function() {
  
  return {
    decode: function(encoded) { 
      return forge.util.hexToBytes(encoded)
    },

    encode: function(bin) {
      return forge.util.bytesToHex(bin)
    }

  };
 
})();

weave.util.BinUtils = (function() {

  return {
    uint8ToString: function(u8a){
      var CHUNK_SZ = 0x8000;
      var c = [];
      for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
      }
      return c.join("");
    },

    binConcat: function() {
      var buf = forge.util.createBuffer();
      for (var i = 0; i < arguments.length; i++) {
        var tmpBuf = forge.util.createBuffer(arguments[i], 'raw');
        buf.putBytes(tmpBuf.getBytes());
      }
      return buf.getBytes();
    }
  }
  
})();

weave.util.UTF8 = (function() {
  return {
    decode: function(encoded) {
      return forge.util.decodeUtf8(encoded);
    },

    encode: function(string) {
      return forge.util.encodeUtf8(string);
    }

  };

})();

weave.util.StringUtils = (function () {

  return {
    STR_PAD_LEFT: 1,
    STR_PAD_RIGHT: 2,
    STR_PAD_BOTH: 3,

    /**
     *
     *  Javascript string pad
     *  http://www.webtoolkit.info/
     *
     **/
    pad: function(str, len, pad, dir) {

      if (typeof(len) == "undefined") { var len = 0; }
      if (typeof(pad) == "undefined") { var pad = ' '; }
      if (typeof(dir) == "undefined") { var dir = STR_PAD_RIGHT; }

      if (len + 1 >= str.length) {

        switch (dir){

        case this.STR_PAD_LEFT:
          str = Array(len + 1 - str.length).join(pad) + str;
          break;

        case this.STR_PAD_BOTH:
          var right = Math.ceil((padlen = len - str.length) / 2);
          var left = padlen - right;
          str = Array(left+1).join(pad) + str + Array(right+1).join(pad);
          break;

        default:
          str = str + Array(len + 1 - str.length).join(pad);
          break;

        } // switch

      }

      return str;      
    },

    leftPad: function(str, len, pad) {
      return this.pad(str, len, pad, this.STR_PAD_LEFT);
    },

    rightPad: function(str, len, pad) {
      return this.pad(str, len, pad, this.STR_PAD_RIGHT);
    }

  };

})();
