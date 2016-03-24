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

//npm includes
var xhr = require('xhr2');
var P   = require('p-promise');

//app includes
var weave = {};
weave.error  = require('../weave-error');
weave.util   = require('../weave-util');
weave.net    = require('../weave-net');
weave.crypto = require('../weave-crypto');

var legacyAccount = {};

legacyAccount.LegacyAccount = function() {
  var storageApiVersion = "v1_1";
  var cryptoApiVersion  = "v5";

  var baseURL  = null;
  var user     = null;
  var password = null;
  var syncKey  = null;

  var storageUrl = null;
  var keyPair    = null;
};

legacyAccount.LegacyAccount.prototype = {  

  init: function(params) {
    this.baseURL  = params.baseURL;
	this.user     = params.user;
	this.password = params.password;
    this.syncKey  = params.syncKey;

    this.getStorageUrl();
    this.getMasterKeyPair();

    return P(true);
  },

  getStorageParams: function() {
    return {
      apiVersion: this.storageApiVersion,
      storageURL: this.storageUrl,
	  user:       this.user,
	  password:   this.password
    };
  },

  getCryptoParams: function() {
    return {
      apiVersion: this.cryptoApiVersion,
      keyPair:    this.keyPair
    };      
  },

  getStorageUrl: function() {
    
    if ( this.storageUrl == null ) {  
	  //TODO - confirm account exists, i.e. /user/1.0/USER returns 1
		
	  var url = URI(sprintf("user/1.0/%s/node/weave", this.user)).absoluteTo(this.baseURL);

	  this.storageUrl = weave.net.Http.get(url, 2000);
    }
    
    return this.storageUrl;
  },

  /**
   * Derive the key pair from the base32 sync key
   */
  getMasterKeyPair: function() {
	weave.util.Log.debug("weave.client.WeaveClient.getPrivateKeyPair()");

	if ( this.keyPair === null ) {
      
	  // Generate key pair using SHA-256 HMAC-based HKDF of sync key
	  // See https://docs.services.mozilla.com/sync/storageformat5.html#the-sync-key
      
	  // Remove dash chars, convert to uppercase and translate 8 and 9 to L and O
	  var syncKeyB32 = this.syncKey.toUpperCase()
		.replace('8', 'L', 'g')
		.replace('9', 'O', 'g')
		.replace("-", "", 'g');

	  weave.util.Log.debug(sprintf("normalised sync key: %s",  syncKeyB32));

	  // Pad base32 string to multiple of 8 chars (40 bits)
	  if ( (syncKeyB32.length % 8) > 0 ) {
		var paddedLength = syncKeyB32.length + 8 - (syncKeyB32.length % 8);
		syncKeyB32 = weave.util.StringUtils.rightPad(syncKeyB32, paddedLength, '=');
	  }

	  var syncKeyBin = weave.util.Base32.decode(syncKeyB32);

      var keyInfo = "Sync-AES_256_CBC-HMAC256" + this.user;

	  // For testing only
	  //syncKeyBin = weave.util.Hex.decode("c71aa7cbd8b82a8ff6eda55c39479fd2")
	  //keyInfo = "Sync-AES_256_CBC-HMAC256" + "johndoe@example.com"

	  weave.util.Log.debug(sprintf("base32 key: %s decoded to %s", this.syncKey, weave.util.Hex.encode(syncKeyBin)));

	  var keyPair = new weave.crypto.WeaveKeyPair();

      var hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.UTF8.encode(keyInfo + "\x01"));
	  keyPair.cryptKey = hmacSHA256.digest();

      hmacSHA256 = forge.hmac.create();
      hmacSHA256.start('sha256', syncKeyBin);
      hmacSHA256.update(weave.util.BinUtils.binConcat(keyPair.cryptKey, weave.util.UTF8.encode(keyInfo + "\x02")));
	  keyPair.hmacKey = hmacSHA256.digest();
	  
	  weave.util.Log.info("Successfully generated sync key and hmac key");
	  weave.util.Log.debug(sprintf("sync key: %s, crypt key: %s, crypt hmac: %s", this.syncKey, weave.util.Hex.encode(keyPair.cryptKey), weave.util.Hex.encode(keyPair.hmacKey)));

      this.keyPair = keyPair;
	}

	return this.keyPair;
  }

};

module.exports = legacyAccount;
