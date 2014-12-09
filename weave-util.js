//npm includes
var sprintf = require('sprintf').sprintf;

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
  
  return {
    XOR: _XOR,
    HtS: _hexToString,
    StH: _stringToHex,
    AtS: _arrayToString,
    StA: _stringToArray,
    intify: _intify,
    clearify: _clearify
  };
  
}();

/*
 * The JavaScript implementation of Base 64 encoding scheme
 * http://rumkin.com/tools/compression/base64.php
 *
 * Modified, 2008, Anant Narayanan <anant@kix.in>
 *
 * Public domain
 */
weave.util.Base64 = function() {
  var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  
  function _encode64(input) {
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
  }

  function _decode64(input) {
    var output = "";
    var chr1, chr2, chr3;
    var enc1, enc2, enc3, enc4;
    var i = 0;
  
    /* remove all characters that are not A-Z, a-z, 0-9, +, /, or = */
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
  
  return {
    encode: _encode64,
    decode: _decode64
  };
  
}();

/*
 * JavaScript implementation of Hex (Base 16) encoding scheme
 * http://snipplr.com/view/52975/string--hex-conversion
 *
 * Modified, 2014, Gerry <nickel_chrome@mac.com>
 *
 * Public domain
 */
weave.util.Hex = function() {
  
  function d2h(d) {
    return d.toString(16);
  }

  function h2d (h) {
    return parseInt(h, 16);
  }

  function _encodeHex(tmp) {
    var str = '',
        i = 0,
        tmp_len = tmp.length,
        c;
    
    for (; i < tmp_len; i += 1) {
        c = tmp.charCodeAt(i);
        str += d2h(c) + ' ';
    }
    return str;
  }

  function _decodeHex(tmp) {
    var arr = tmp.split(' '),
        str = '',
        i = 0,
        arr_len = arr.length,
        c;
    
    for (; i < arr_len; i += 1) {
        c = String.fromCharCode( h2d( arr[i] ) );
        str += c;
    }
    
    return str;
  }
  
  return {
    encode: _encodeHex,
    decode: _decodeHex
  };
  
}();
