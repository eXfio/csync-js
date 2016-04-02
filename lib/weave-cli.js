/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave Sync commandline interface
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

//nodejs includes
//var util = require('util');

//npm includes
var Getopt  = require('node-getopt');
var sprintf = require('sprintf').sprintf;
var P       = require('p-promise');

//app includes
var weave = require('../weaveclient');

//console.log(util.inspect(weave));

var accountServer = null;
var tokenServer   = null;
var username   = null;
var password   = null;
var synckey    = null;
var email      = null;
var collection = null;
var id         = null;
var payload    = null;
var remove     = false;
var info       = false;
var encrypt    = true;
var logLevel   = null;
var apiVersion = null;

var weaveParams = null;
var weaveAccount = null;
var weaveClient = null;

// Parse commandline arguments
var getopt = new Getopt([
  ["h", "help", "print this message"],
  ["s", "account-server=ARG", "Account server URL"],
  ["t", "token-server=ARG", "Token server URL"],
  ["u", "username=ARG", "username"],
  ["p", "password=ARG", "password"],
  ["k", "sync-key=ARG", "sync key (required for API v1.1)"],
  ["c", "collection=ARG", "collection"],
  ["i", "id=ARG", "object ID"],
  //["n", "info", "get collection info. Requires -c"],  
  //["o", "ids", "get collection ids. Requires -c"],  
  ["", "plaintext", "do not encrypt/decrypt item"],
  ["m", "modify=ARG", "update item with given value in JSON format. Requires -c and -i"],
  ["d", "delete", "delete item. Requires -c and -i"],
  ["l", "log-level=ARG", "set log level (trace|debug|info|warn|error)"],
  ["v", "api-version=ARG", "api version (1.1|1.5). Defaults to 1.1"]
]);
                        
getopt.bindHelp();
		
var cmd = getopt.parseSystem();
		
if ( 'help' in cmd.options ) {
  // help
  getopt.showHelp();
  process.exit(0);
}

//Need to set log level BEFORE instansiating Logger
logLevel = 'warn';
if ( 'log-level' in cmd.options ) {
  logLevel = cmd.options['log-level'].toString().toLowerCase();
  if ( !logLevel.match("^trace|debug|info|warn|error\$") ) {
	process.stderr.write("log level must be one of (trace|debug|info|warn|error)\n");
	process.exit(1);
  }
}
weave.util.Log.setLevel(logLevel);

//Set collection
collection = 'collection' in cmd.options ? cmd.options['collection'] : null;
if ( collection === null || collection == "" ) {
  process.stderr.write("collection is a required parameter\n");
  process.exit(1);
}

//Optionally get ID
if ( 'id' in cmd.options ) {
  id = cmd.options['id'];
}

if ( 'modify' in cmd.options ) {
  if ( id === null ) {
	process.stderr.write("id is required when using the modify option\n");
	process.exit(1);
  }
  payload = cmd.options['modify'];
}

if ( 'delete' in cmd.options ) {
  if ( id === null ) {
	process.stderr.write("id is required when using the delete option\n");
	process.exit(1);
  } else if ( payload !== null ) {
	process.stderr.write("the modify and delete options cannot be used together\n");
	process.exit(1);
  }
  remove = true;
}

if ( 'plaintext' in cmd.options ) {
  encrypt = false;
}

apiVersion = '1.1';
if ( 'api-version' in cmd.options ) {
  apiVersion = cmd.options['api-version'].toString();
}

if ( apiVersion == '1.5' ) {

  //Set host and credential details
  accountServer = 'account-server' in cmd.options ? cmd.options['account-server'] : null;
  tokenServer   = 'token-server' in cmd.options ? cmd.options['token-server'] : null;
  username      = 'username' in cmd.options ? cmd.options['username'] : null;
  password      = 'password' in cmd.options ? cmd.options['password'] : null;
  
  if (
    (accountServer === null || accountServer == "")
      ||
    (tokenServer === null || tokenServer == "")
      ||
    (username === null || username == "")
      ||
    (password === null || password == "")
  ) {
    process.stderr.write("account-server, token-server, username and password are required parameters\n");
    process.exit(1);
  }
  
  var weaveParams = {
    accountServer: accountServer,
    tokenServer: tokenServer,
    user: username,
    password: password
  };

  weaveAccount = new weave.account.fxa.FxAccount();

} else if ( apiVersion == '1.1' ) {

  //Set host and credential details
  accountServer = 'account-server' in cmd.options ? cmd.options['account-server'] : null;
  username      = 'username' in cmd.options ? cmd.options['username'] : null;
  password      = 'password' in cmd.options ? cmd.options['password'] : null;
  synckey       = 'sync-key' in cmd.options ? cmd.options['sync-key'] : null;
  
  if (
    (accountServer === null || accountServer == "")
      ||
    (username === null || username == "")
      ||
    (password === null || password == "")
      ||
    (synckey === null || synckey == "")
  ) {
    process.stderr.write("account-server, username, password and synckey are required parameters\n");
    process.exit(1);
  }
  
  var weaveParams = {
    accountServer: accountServer,
    user: username,
    password: password,
    syncKey: synckey
  };

  weaveAccount = new weave.account.legacy.LegacyAccount();
}

initWeaveAccount()
  .then(
    function() {
      return initWeaveClient();
    }
  )
  .then(
    function() {
      return syncServerRequest();
    }
  )
  .fail(
    function(error) {
      process.stderr.write(error + "\n");
      process.exit(1);
    }
  );

function initWeaveAccount() {
  weave.util.Log.debug("initWeaveAccount()");
  return weaveAccount.init(weaveParams);
}

function initWeaveClient() {  
  weave.util.Log.debug("initWeaveClient()");
  try {
    weaveClient = weave.client.WeaveClientFactory.getInstance(weaveAccount);
    return P(true);
  } catch(e) {
    throw new weave.errorWeaveError("Couldn't instantiate WeaveClient - " + e.message);
    return P.reject(e.message);
  }
}

function syncServerRequest() {
  weave.util.Log.debug("syncServerRequest()");
    
  if ( payload !== null ) {

    var wbo = new weave.storage.WeaveBasicObject();
    wbo.id      = id;
    wbo.payload = payload;

    weaveClient.put(collection, id, wbo, encrypt)
      .then(function(modified) {
	    process.stdout.write(sprintf("modified: %f\n", modified));
      })
      .fail(function(error) {
	    process.stderr.write(error + "\n");
	    process.exit(1);
      });      

  } else if ( remove ) {
    
	if ( id !== null ) {
	  weaveClient.delete(collection, id)
        .then(function(modified) {
	      process.stdout.write(sprintf("modified: %f\n", modified));
        })
        .fail(function(error) {
	      process.stderr.write(error + "\n");
	      process.exit(1);
        });
	} else {
	  weaveClient.deleteCollection(collection)
        .then(function(modified) {
	      process.stdout.write(sprintf("modified: %f\n", modified));
        })
        .fail(function(error) {
	      process.stderr.write(error + "\n");
	      process.exit(1);
        }); 
	}
    
  } else {
    
	if ( id !== null ) {
	  weaveClient.get(collection, id, encrypt)
        .then(function(wbo) {
	      process.stdout.write(wbo.payload + "\n");
        })
        .fail(function(error) {
	      process.stderr.write(error + "\n");
	      process.exit(1);
        });      
	} else {
	  weaveClient.getCollection(collection, null, null, null, null, null, null, null, null, null, encrypt)
        .then(function(colWbo) {
	      for (var i = 0; i < colWbo.length; i++) {
            process.stdout.write(colWbo[i].payload + "\n");
	      }	
        })
        .fail(function(error) {
	      process.stderr.write(error + "\n");
	      process.exit(1);
        });
	}
  }
}
