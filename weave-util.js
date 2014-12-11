//npm includes
var sprintf     = require('sprintf').sprintf;

//Module DOES NOT correctly support binary data
//var binstring   = require('binstring');
//var base32 = require('base32');
//var base32 = require('thirty-two');

//app includes
var weave = require('./weave-include');

weave.util = {};

weave.util.Utils = function() {
  function _XOR(a, b, isA) {
    if (a.length != b.length) {
      return false;
    }
    
    var val = [];
    for (var i = 0; i < a.length; i++) {
      if (isA) {
        val[i] = a[i] ^ b[i];
      } else {
        val[i] = a.charCodeAt(i) ^ b.charCodeAt(i);
      }
    }
    
    return val;
  }
  
  function _stringToHex(str) {
    var ret = '';
    for (var i = 0; i < str.length; i++) {
      var num = str.charCodeAt(i);
      var hex = num.toString(16);
      if (hex.length == 1) {
        hex = '0' + hex;
      }
      ret += hex;
    }
    return ret;
  }
  
  function _hexToString(hex) {
    var ret = '';
    if (hex.length % 2 != 0) {
      return false;
    }
    
    for (var i = 0; i < hex.length; i += 2) {
      var cur = hex[i] + hex[i + 1];
      ret += String.fromCharCode(parseInt(cur, 16));
    }
    return ret;
  }
  
  function _arrayToString(arr) {
    var ret = '';
    for (var i = 0; i < arr.length; i++) {
      ret += String.fromCharCode(arr[i]);
    }
    return ret;
  }

  function _stringToArray(str) {
    var ret = [];
    for (var i = 0; i < str.length; i++) {
      ret[i] = str.charCodeAt(i);
    }
    return ret;
  }
  
  function _intify(str) {
    ret = '';
    for (var i = 0; i < str.length; i++) {
      var cur = str.charCodeAt(i);
      ret += String.fromCharCode(cur & 0xff);
    }
    
    return ret;
  }
  
  function _clearify(str) {
    ret = '';
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code >= 32 && code <= 126) {
        ret += String.fromCharCode(code);
      }
    }
    
    return ret;
  }

  function _base32Decode(base32EncodedString) {
    /// <summary>Decodes a base32 encoded string into a Uin8Array, note padding is not supported</summary>
    /// <param name="base32EncodedString" type="String">The base32 encoded string to be decoded</param>
    /// <returns type="Uint8Array">The Unit8Array representation of the data that was encoded in base32EncodedString</returns>
    if (!base32EncodedString && base32EncodedString !== "") {
        throw "base32EncodedString cannot be null or undefined";
    }

    if (base32EncodedString.length * 5 % 8 !== 0) {
        throw "base32EncodedString is not of the proper length. Please verify padding.";
    }

    base32EncodedString = base32EncodedString.toLowerCase();
    var alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    var returnArray = new Array(base32EncodedString.length * 5 / 8);

    var currentByte = 0;
    var bitsRemaining = 8;
    var mask = 0;
    var arrayIndex = 0;

    for (var count = 0; count < base32EncodedString.length; count++) {
        var currentIndexValue = alphabet.indexOf(base32EncodedString[count]);
        if (-1 === currentIndexValue) {
            if ("=" === base32EncodedString[count]) {
                var paddingCount = 0;
                for (count = count; count < base32EncodedString.length; count++) {
                    if ("=" !== base32EncodedString[count]) {
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
                throw "base32EncodedString contains invalid characters or invalid padding.";
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
    return _uint8ToString(retval);
  };

  function _uint8ToString(u8a){
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
      c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
    }
    return c.join("");
  }

  return {
    XOR: _XOR,
    HtS: _hexToString,
    StH: _stringToHex,
    AtS: _arrayToString,
    StA: _stringToArray,
    B32tS: _base32Decode,
    intify: _intify,
    clearify: _clearify
  };
  
}();

/*
 * The JavaScript implementation of Base 64 encoding scheme
 * http://rumkin.com/tools/compression/base64.php
 *
 * Modified, 2008, Anant Narayanan <anant@kix.in>
 * Modified, 2014, Gerry Healy <nickel_chrome@mac.com>
 *
 * Public domain
 */
weave.util.Base64 = (function() {
  var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  
  return {
    encode: function(input) {
      var i = 0;
      var output = "";
      var chr1, chr2, chr3;
      var enc1, enc2, enc3, enc4;
      
      do {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
        
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
          enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
          enc4 = 64;
        }

        output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
      } while (i < input.length);

      return output;
    },

    decode: function(input) {
      var output = "";
      var chr1, chr2, chr3;
      var enc1, enc2, enc3, enc4;
      var i = 0;
      
      ///* remove all characters that are not A-Z, a-z, 0-9, +, /, or = */
      input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
      
      do {
        enc1 = keyStr.indexOf(input.charAt(i++));
        enc2 = keyStr.indexOf(input.charAt(i++));
        enc3 = keyStr.indexOf(input.charAt(i++));
        enc4 = keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 != 64) {
          output = output + String.fromCharCode(chr2);
        }

        if (enc4 != 64) {
          output = output + String.fromCharCode(chr3);
        }
      } while (i < input.length);
      
      return output;
    }
  
  };
  
})();

/*
//base32 module broken
weave.util.Base32 = (function() {

  return {
    decode: function(encoded) { 
      return base32.decode(encoded);
    },

    encode: function(bin) {
      return base32.encode(bin);
    }

  };

})();

//thirty-two module broken
weave.util.Base32 = (function() {

  return {
    decode: function(encoded) { 
      return base32.decode(encoded).toString();
    },

    encode: function(bin) {
      return base32.encode(bin).toString();
    }

  };

})();
*/

weave.util.Base32 = (function() {

  return {
    decode: function(encoded) { 
      return weave.util.Utils.B32tS(encoded);
    },

    encode: function(bin) {
      throw new weave.WeaveError("Base 32 encode not supported");
    }

  };

})();

/*
//binstring module broken
weave.util.Hex = (function() {
  
  return {
    decode: function(hex) { 
      return binstring(hex, {in: 'hex', out: 'binary'});
    },

    encode: function(bin) {
      return binstring(bin, {in: 'binary', out: 'hex'});
    }

  };
 
})();
*/

weave.util.Hex = (function() {
  
  return {
    decode: function(encoded) { 
      return weave.util.Utils.HtS(encoded)
    },

    encode: function(bin) {
      return weave.util.Utils.StH(bin)
    }

  };
 
})();


/*global JXG: true, define: true, escape: true, unescape: true*/
/*jslint nomen: true, plusplus: true, bitwise: true*/

/* depends:
 jxg
 */

weave.util.UTF8 = (function() {

  // constants
  var UTF8_ACCEPT = 0;
  var UTF8_REJECT = 12;
  var UTF8D = [
    // The first part of the table maps bytes to character classes that
    // to reduce the size of the transition table and create bitmasks.
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,   7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    10, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3,  11, 6, 6, 6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,

    // The second part is a transition table that maps a combination
    // of a state of the automaton and a character class to a state.
    0, 12, 24, 36, 60, 96, 84, 12, 12, 12, 48, 72,  12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12,  0, 12, 12, 12, 12, 12,  0, 12,  0, 12, 12,  12, 24, 12, 12, 12, 12, 12, 24, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12,  12, 24, 12, 12, 12, 12, 12, 12, 12, 24, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12,  12, 36, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12,
    12, 36, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12
  ];

  /**
   * Extends the standard charCodeAt() method of the String class to find the ASCII char code of
   * a character at a given position in a UTF8 encoded string.
   * @param {String} str
   * @param {Number} i position of the character
   * @return {Number}
   */
  function asciiCharCodeAt(str, i) {
    var c = str.charCodeAt(i);

    if (c > 255) {
      switch (c) {
      case 8364:
        c = 128;
        break;
      case 8218:
        c = 130;
        break;
      case 402:
        c = 131;
        break;
      case 8222:
        c = 132;
        break;
      case 8230:
        c = 133;
        break;
      case 8224:
        c = 134;
        break;
      case 8225:
        c = 135;
        break;
      case 710:
        c = 136;
        break;
      case 8240:
        c = 137;
        break;
      case 352:
        c = 138;
        break;
      case 8249:
        c = 139;
        break;
      case 338:
        c = 140;
        break;
      case 381:
        c = 142;
        break;
      case 8216:
        c = 145;
        break;
      case 8217:
        c = 146;
        break;
      case 8220:
        c = 147;
        break;
      case 8221:
        c = 148;
        break;
      case 8226:
        c = 149;
        break;
      case 8211:
        c = 150;
        break;
      case 8212:
        c = 151;
        break;
      case 732:
        c = 152;
        break;
      case 8482:
        c = 153;
        break;
      case 353:
        c = 154;
        break;
      case 8250:
        c = 155;
        break;
      case 339:
        c = 156;
        break;
      case 382:
        c = 158;
        break;
      case 376:
        c = 159;
        break;
      default:
        break;
      }
    }
    return c;
  }

  return {
    /**
     * Encode a string to utf-8.
     * @param {String} string
     * @return {String} utf8 encoded string
     */
    encode : function (string) {
      var n, c,
      utftext = '',
      len = string.length;

      string = string.replace(/\r\n/g, '\n');

      // See
      // http://ecmanaut.blogspot.ca/2006/07/encoding-decoding-utf8-in-javascript.html
      // http://monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
      if (typeof unescape === 'function' && typeof encodeURIComponent === 'function') {
        return unescape(encodeURIComponent(string));
      }

      for (n = 0; n < len; n++) {
        c = string.charCodeAt(n);

        if (c < 128) {
          utftext += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
          utftext += String.fromCharCode((c >> 6) | 192);
          utftext += String.fromCharCode((c & 63) | 128);
        } else {
          utftext += String.fromCharCode((c >> 12) | 224);
          utftext += String.fromCharCode(((c >> 6) & 63) | 128);
          utftext += String.fromCharCode((c & 63) | 128);
        }

      }

      return utftext;
    },

    /**
     * Decode a string from utf-8.
     * @param {String} utftext to decode
     * @return {String} utf8 decoded string
     */
    decode : function (utftext) {
      /*
        The following code is a translation from C99 to JavaScript.

        The original C99 code can be found at
        http://bjoern.hoehrmann.de/utf-8/decoder/dfa/

        Original copyright note:

        Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>

        License: MIT License (see LICENSE.MIT)
      */

      var i, charCode, type,
      j = 0,
      codepoint = 0,
      state = UTF8_ACCEPT,
      chars = [],
      len = utftext.length,
      results = [];

      for (i = 0; i < len; i++) {
        charCode = utftext.charCodeAt(i);
        type = UTF8D[charCode];

        if (state !== UTF8_ACCEPT) {
          codepoint = (charCode & 0x3f) | (codepoint << 6);
        } else {
          codepoint = (0xff >> type) & charCode;
        }

        state = UTF8D[256 + state + type];

        if (state === UTF8_ACCEPT) {
          if (codepoint > 0xffff) {
            chars.push(0xD7C0 + (codepoint >> 10), 0xDC00 + (codepoint & 0x3FF));
          } else {
            chars.push(codepoint);
          }

          j++;

          if (j % 10000 === 0) {
            results.push(String.fromCharCode.apply(null, chars));
            chars = [];
          }
        }
      }
      results.push(String.fromCharCode.apply(null, chars));
      return results.join("");
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
