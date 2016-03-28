var sprintf = require('sprintf');
var P = require('p-promise');

var weave = {};
weave.util   = require('../lib/weave-util');
weave.crypto = require('../lib/weave-crypto');

//-----------------------
// HKDF globals
//-----------------------
var ikmHex = "7130a3c4e827f4b354b86395e29e0722d156cb3afd08d990da0340a0a6623173";  

//-----------------------
// Hawk globals
//-----------------------
var hawkurl = "https://cucumbersync.com/storage/1.5/2";
var hawkmethod = 'GET';
var hawkid  = "eyJub2RlIjogImh0dHBzOi8vY3VjdW1iZXJzeW5jLmNvbSIsICJleHBpcmVzIjogMTQ1ODgxNDYxNiwgInNhbHQiOiAiZTdmMTdlIiwgInVpZCI6IDJ97wQ8DQ_VJRPYh-qHbUJ4pRmp02RLubaxsJsRKWPMm-Y";
var hawkkey = "a1mpRYzHzUlr6DYureEyqxTa9mDq4WWW2OjF5Ixurlw=";
var hawknonce = "GmJFkm";

testHkdf()
  .then(testHawk());

//-----------------------
// HKDF tests
//-----------------------
function testHkdf() {

  return forgeHkdf()
    .then(sjclHkdf());
}

function forgeHkdf() {
  weave.util.Log.info("forgeHkdf()");

  var forge = require('node-forge');

  var ikm = forge.util.createBuffer(weave.util.Hex.decode(ikmHex));
  var info = forge.util.createBuffer("identity.mozilla.com/picl/v1/oldsync");
  var salt = forge.util.createBuffer();
  
  return weave.crypto.HKDF.derive(
    ikm,
    info,
    salt,
    2*32
  ).then(
    function(derived) {
	  weave.util.Log.info("Forge derived: " + derived.toHex());
      
      //var keyPair = {
	  //  cryptKey: forge.util.createBuffer(derived.getBytes(32)),
	  //  hmacKey:  forge.util.createBuffer(derived.getBytes())
      //};
      
      //weave.util.Log.debug("Successfully generated key pair");
	  //weave.util.Log.debug(sprintf("ikm: %s, crypt key: %s, hmac key: %s", ikm.toHex(), keyPair.cryptKey.toHex(), keyPair.hmacKey.toHex()));
      return P(true);
    },
    function(error) {
      weave.util.Log.error("Couldn't generate key pair - " + error);
      return P.reject(error);
    }
  );
}

function sjclHkdf() {
  weave.util.Log.info("sjclHkdf()");
  
  var hkdf = require('../node_modules/fxa-js-client/client/lib/hkdf');
  var sjcl = require('sjcl');
  
  var ikm =  sjcl.codec.hex.toBits(ikmHex);
  var info = sjcl.codec.utf8String.toBits("identity.mozilla.com/picl/v1/oldsync");
  var salt = sjcl.codec.hex.toBits('');
  
  return hkdf(
    ikm,
    info,
    salt,
    2*32
  ).then(
    function(derived) {
	  weave.util.Log.info("Sjcl derived: " + sjcl.codec.hex.fromBits(derived));
      
      //var keyPair = {
	  //  cryptKey: forge.util.createBuffer(derived.getBytes(32)),
	  //  hmacKey:  forge.util.createBuffer(derived.getBytes())
      //};
      
      //weave.util.Log.debug("Successfully generated key pair");
	  //weave.util.Log.debug(sprintf("ikm: %s, crypt key: %s, hmac key: %s", ikm.toHex(), keyPair.cryptKey.toHex(), keyPair.hmacKey.toHex()));
      return P(true);
    },
    function(error) {
      weave.util.Log.error("Couldn't generate key pair - " + error);
      return P.reject(error);
    }
  );
}

//-----------------------
// HAWK tests
//-----------------------
function testHawk() {
  return origHawk()
    .then(fxaHawk());
}

function origHawk() {
  weave.util.Log.info("origHawk()");

  var hawk = require('hawk');

  var creds = {
	'id': hawkid,
	'key': hawkkey,
	'algorithm': "sha256"
  };

  var header = hawk.client.header(hawkurl, hawkmethod, {"credentials": creds, "ext": "", "nonce": hawknonce});
  
  weave.util.Log.debug("Orig Hawk Header: " + header.field);

  return P(true);
}

function fxaHawk() {
  weave.util.Log.info("fxaHawk()");
  
  var hawk = require('../node_modules/fxa-js-client/client/lib/hawk');

  var creds = {
	'id': hawkid,
	'key': hawkkey,
	'algorithm': "sha256"
  };

  var header = hawk.client.header(hawkurl, hawkmethod, {"credentials": creds, "ext": "", "nonce": hawknonce});
  
  weave.util.Log.debug("FxA Hawk Header: " + header.field);

  return P(true);

}
