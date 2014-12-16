weaveclient-js
==============

Weave Sync/Firefox Sync client library written in JavaScript.

## Features
* Compatible with Weave Sync v5 (pre Firefox 29)
* Decrypt data stored on Weave Sync server (read only)
* Commandline client

## Node

### Installation
```
npm install weaveclient
```

### Basic Usage

```javascript
var weave = require('weaveclient');

var baseURL  = "http://server/path/to/weave";
var user     = "username";
var password = "really long password";
var synckey  = "CBGMDB56ISI5KVQWDIUB2K54HQ"; //Base32 encoded sync key

var weaveClient = new weave.client.WeaveClient();
weaveClient.init(baseURL, username, password, synckey);

var collection = "bookmarks";

var colWbo = weaveClient.getCollection(collection, null, null, null, null, null, null, null, null, null, true);
for (var i = 0; i < colWbo.length; i++) {
  process.stdout.write(colWbo[i].payload + "\n");
}

var id = "FprxRkbQsyKe" #Base64 encoded object id (unique within collection)
var wbo = weaveClient.get(collection, id, true);
process.stdout.write(col.payload + "\n");
```

## Commandline Client
```
Usage: weaveclient

  -h, --help            print this message
  -s, --server=ARG      server URL
  -u, --username=ARG    username
  -p, --password=ARG    password
  -k, --sync-key=ARG    sync key (required for storage v5)
  -c, --collection=ARG  collection
  -i, --id=ARG          object ID
  -t, --plaintext       do not encrypt/decrypt item
  -m, --modify=ARG      update item with given value in JSONUtils format. Requires -c and -i
  -d, --delete          delete item. Requires -c and -i
  -l, --log-level=      set log level (trace|debug|info|warn|error)
```
