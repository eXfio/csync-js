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

//jam inclues
requirejs(['sprintf']);
requirejs(['node-forge']);

//other third party includes
requirejs(['lib/json']);

//app files
requirejs(['./weave-include']);
requirejs(['./weave-util']);

weave.crypto.PayloadCipher = function() {

    function decrypt(payload, keyPair) {
		var cleartext     = null;
		var encryptObject = null;
		
        // Parse JSON encoded payload
		try {
			encryptObject = JSON.parse(payload);
		} catch (e) {
			throw new weave.WeaveError(e);
		}
        
        // An encrypted payload has three relevant fields
        var ciphertext  = encryptObject.ciphertext;
        var cipherbytes = Weave.Util.Base64.decode(ciphertext);
        var iv          = Weave.Util.Base64.decode(encryptObject.IV);
        var cipher_hmac = encryptObject.hmac;
                    
        weave.Log.debug( sprintf("payload: %s, crypt key:  %s, crypt hmac: %s", payload, Weave.Util.Hex.encode(keyPair.cryptKey), Weave.Util.Hex.encode(keyPair.hmacKey)));
            
            
        // 1. Validate hmac of ciphertext
        // Note: HMAC verification is done against base64 encoded ciphertext
        var local_hmac = null;
        
        try {
            var hmacSHA256 = forge.hmac.create();
            hmacSHA256.start('sha256', keyPair.hmacKey);
            hmacSHA256.update(ciphertext);
            local_hmac = hmac256.digest().toHex();
		} catch (e) {
			throw new weave.WeaveError(e);
		}
        
        if ( local_hmac !== cipher_hmac ) {
        	weave.Log.warn(sprintf("cipher hmac: %s, local hmac: %s", cipher_hmac, local_hmac));
        	throw new weave.WeaveError("HMAC verification failed!");
        }
            
        // 2. Decrypt ciphertext
        // Note: this is the same as this operation at the openssl command line:
        // openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`
        try {

        	var cipher = forge.cipher.createDecipher('AES-CBC', keyPari.cryptKey); ///PKCS5Padding");
        	cipher.start({iv: iv)};
        	cipher.update(cipherbytes);
            cipher.finish();
        	cleartext = cipher.output.toString();
        	
            weave.Log.debug(sprintf("cleartext: %s", cleartext));

		} catch (e) {
			throw new weave.WeaveError(e);
        }

        weave.Log.info("Successfully decrypted v5 data record");
        
		return cleartext;
	}


	/**
	 * encrypt()
	 *
	 * Given a plaintext object, encrypt it and return the ciphertext value.
	 */
    function encrypt(plaintext, keyPair) {
		weave.Log.debug("encrypt()");
		weave.Log.debug("plaintext:\n" + plaintext);
	        
        weave.Logdebug(sprintf("payload: %s, crypt key:  %s, crypt hmac: %s", plaintext, Weave.Util.Hex.encode(keyPair.cryptKey), Weave.Util.Hex.encode(keyPair.hmacKey)));
		        
		// Encryption primitives
        var ciphertext  = null;
        var cipherbytes = new array();
        var iv          = new array();
        var hmac        = new array();
        
        // 1. Encrypt plaintext
        // Note: this is the same as this operation at the openssl command line:
        // openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`
		
        try {
            iv = forge.random.getBytesSync(16);

        	var cipher = forge.cipher.createCipher('AES-CBC', keyPair.cryptKey);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(plaintext));
            cipher.finish();
        	cipherbytes = cipher.output;

        } catch (e) {
			throw new weave.WeaveError(e);
        }
        
        // 2. Create hmac of ciphertext
        // Note: HMAC is done against base64 encoded ciphertext
    	ciphertext = Weave.Util.Base64.encode(cipherbytes);
    	
    	try {
            var hmacSHA256 = forge.hmac.create();
            hmacSHA256.start('sha256', keyPair.hmacKey);
            hmacSHA256.update(ciphertext);
            hmac = hmac256.digest().toHex();

		} catch (e) {
			throw new weave.WeaveError(e);
		}

		weave.Log.info("Successfully encrypted v5 data record");

        // Construct JSONUtils encoded payload
		var encryptObject = {};
		encryptObject.ciphertext = ciphertext;
		encryptObject.IV         = Weave.Util.Base64.encode(iv);
		encryptObject.hmac       = Weave.Util.Hex.encode(hmac);
		
		return JSON.stringify(encryptObject);
	}	
}

weave.crypto.WeaveKeyPair = function() {

	var cryptKey;
    var hmacKey;
}
