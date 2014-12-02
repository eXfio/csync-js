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

requirejs.config({
  baseUrl: 'jam'
});

//jam inclues
requirejs(['sprintf']);

//app files
requirejs(['./weave-crypto']);
requirejs(['./weave-include']);
requirejs(['./weave-util']);

weave.client.WeaveClient = function() {

  var KEY_CRYPTO_PATH       = "crypto/keys";
  var KEY_CRYPTO_COLLECTION = "crypto";
  var KEY_CRYPTO_ID         = "keys";
  var KEY_META_PATH         = "meta/global";
  var KEY_META_COLLECTION   = "meta";
  var KEY_META_ID           = "global";
  
  var account;
  var storageClient;
  var regClient;
  var privateKey
  var bulkKeys;

  function init(baseURL, user, password, syncKey) {
	this.privateKey      = null;
	this.bulkKeys        = null;

	//Store account params
	this.account = {};
	this.account.baseURL  = baseURL;
	this.account.user     = user;
	this.account.password = password;
	this.account.syncKey  = syncKey;
	
	//Initialise registration and storage clients with account details
	this.regClient = new weave.client.RegistrationApi();
	this.regClient.init(baseURL, user, password);
	this.storageClient = new weave.client.StorageApi();
	this.storageClient.init(this.regClient.getStorageUrl(), user, password);
  }
  
  function decryptWeaveBasicObject(wbo, collection) {
	if ( !isEncrypted(wbo) ) {
	  throw new weave.WeaveError("Weave Basic Object already decrypted");
	}
    
	var payload = decrypt(wbo.getPayload(), collection);
	return new weave.client.WeaveBasicObject(wbo.getId(), wbo.getModified(), wbo.getSortindex(), wbo.getTtl(), payload);
  }
  
  function decrypt(payload, collection) {
    
    var keyPair = new weave.crypto.WeaveKeyPair();
    
    if ( collection === null ) {
      Weave.Log.info("Decrypting data record using sync key");
      
      try {
        keyPair = getPrivateKeyPair();
      } catch(e){
        throw new weave.WeaveError(e.message);
      }
      
    } else {
      Weave.Log.info(sprintf("Decrypting data record using bulk key %s", collection));
      
      keyPair = getBulkKeyPair(collection);
    }
    
    cipher = new weave.crypto.PayloadCipher();
    
    return cipher.decrypt(payload, keyPair);
  }
  
  function get(collection, id, decrypt, callback) {
    if (decrypt) {
	  this.storageClient.get(collection, id, function(wbo) {callback(this.decryptWeaveBasicObject(wbo, collection));});
    } else {
	  this.storageClient.get(collection, id, callback);
    }
  }
  
}

weave.client.RegistrationApi = function() {
  
  var baseURL  = null;
  var user     = null;
  var password = null;
  
  function init(baseURL, user, password) {
    this.baseURL  = baseURL;
	this.user     = user;
	this.password = password;
  }
  
  function getStorageUrl() throws WeaveException {
      
	storageURL = null;
	
	//TODO - confirm account exists, i.e. /user/1.0/USER returns 1
		
	var location = URI(sprintf("user/1.0/%s/node/weave", this.user)).relativeTo(baseURL);

	HttpGet get = new HttpGet(location);
	CloseableHttpResponse response = null;

		try {
			response = httpClient.execute(get);
			HttpClient.checkResponse(response);
			
			storageURL = new URI(EntityUtils.toString(response.getEntity()));

		} catch (IOException e) {
			throw new WeaveException(e);
		} catch (HttpException e) {
			throw new WeaveException(e);
		} catch (URISyntaxException e) {
			throw new WeaveException(e);
		} finally {
			HttpClient.closeResponse(response);
		}
		
		return storageURL;
	}
}

weave.client.StorageApi = function() {

  var storageURL;
  var user;
  var password;

  function init(storageURL, user, password) {
    this.storageURL = storageURL;
    this.user       = user;
    this.password   = password;
  }
  
  function get(collection, id, callback) {
	weave.Log.debug("get()");
	getPath(collection + "/" + id, callback);
  }

  function getPath(path, callback) {
	weave.Log.debug("getPath()");

    var location = URI(sprintf("1.1/%s/storage/%s", this.user, path)).relativeTo(this.storageURL);
    
    weave.util.Net.get(location, 2000, this.processWeavePayload, callback);
  }
	

  function processWeavePayload(callback) {
	//parse content to extract JSON encoded WeaveBasicObject

    var jsonObject = JSON.parse(this.responseText);

    var wbo = new weave.client.WeaveBasicObject();

	wbo.id         = jsonObject.id
	wbo.modified   = jsonObject.modified;
	wbo.sortindex  = jsonObject.sortindex;
	wbo.payload    = jsonObject.payload;
	wbo.ttl        = jsonObject.ttl;

    callback(wbo);
  }

  function getCollectionIds(collection, ids, older, newer, index_above, index_below, limit, offset, sort) {
    
  }
  
  function getCollection(collection, ids, older, newer, index_above, index_below, limit, offset, sort, format) {
    
  }
  
  function getCollection(location) {
    
  }
}
