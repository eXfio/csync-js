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
var util = require('util');

//npm includes
var Getopt  = require('node-getopt');
var sprintf = require('sprintf').sprintf;

//app includes
var weave = require('./weave-include');
require('./weave-client');

//console.log(util.inspect(weave));

var baseURL    = null;
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
		
// Parse commandline arguments
var getopt = new Getopt([
  ["h", "help", "print this message"],
  ["s", "server=ARG", "server URL"],
  ["u", "username=ARG", "username"],
  ["p", "password=ARG", "password"],
  ["k", "sync-key=ARG", "sync key (required for storage v5)"],
  ["c", "collection=ARG", "collection"],
  ["i", "id=ARG", "object ID"],
  ["t", "plaintext", "do not encrypt/decrypt item"],
  ["m", "modify=ARG", "update item with given value in JSONUtils format. Requires -c and -i"],
  ["d", "delete", "delete item. Requires -c and -i"],
  ["l", "log-level=", "set log level (trace|debug|info|warn|error)"]
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

//Set host and credential details from command line
baseURL  = 'server' in cmd.options ? cmd.options['server'] : null;
username = 'username' in cmd.options ? cmd.options['username'] : null;
password = 'password' in cmd.options ? cmd.options['password'] : null;
synckey  = 'sync-key' in cmd.options ? cmd.options['sync-key'] : null;

if (
  (baseURL === null || baseURL == "")
    ||
  (username === null || username == "")
    ||
  (password === null || password == "")
    ||
  (synckey === null || synckey == "")
) {
  process.stderr.write("server, username, password and synckey are required parameters\n");
  process.exit(1);
}

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

var weaveClient = new weave.client.WeaveClient();
try {
  weaveClient.init(baseURL, username, password, synckey);
} catch(e) {
  process.stderr.write(e.message);
  process.exit(1);
}

if ( payload !== null ) {
  
  var wbo = new weave.client.WeaveBasicObject();
  wbo.id      = id;
  wbo.payload = payload;
  
  var modified = null;
  try {
	modified = weaveClient.put(collection, id, wbo, encrypt);
  } catch(e) {
	process.stderr.write(e.message + "\n");
	process.exit(1);
  }
  console.log(sprintf("modified: %f", modified));
  
} else if ( remove ) {
  
  try {
	weaveClient.delete(collection, id);
  } catch (e) {
	process.stderr.write(e.message + "\n");
	process.exit(1);
  }
  
  //TODO - Handle collections
  
} else {
  
  try {
	if ( id !== null ) {
	  var wbo = weaveClient.get(collection, id, encrypt);
	  process.stdout.write(wbo.payload + "\n");
	} else {
	  var colWbo = weaveClient.getCollection(collection, null, null, null, null, null, null, null, null, null, encrypt);
	  for (var i = 0; i < colWbo.length; i++) {
		process.stdout.write(colWbo[i].payload + "\n");
	  }	
	}
  } catch(e) {
	process.stderr.write(e.message + "\n");
	process.exit(1);
  }
}
