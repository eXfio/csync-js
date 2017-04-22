cucumbersync-js
==============

Cucumber Sync client library written in JavaScript.

Cucumber Sync implements Weave Sync/Firefox Sync crypto version 5 and supports a number of account and storage backends

## Features
* Account and storage backends:
  * Firefox Account (FxA) with Storage API v1.5
  * Weave Sync Account v1.0 with Storage API v1.1 (pre Firefox v29)
* Encrypt/Decrypt data (read and write)
* Commandline client

## Roadmap
* Support for Google Firebase accounts and storage

## Node

### Installation
```
npm install cucumbersync
```

### Basic Usage

```javascript
var weave = require('cucumbersync');

var baseURL  = "http://server/path/to/csync";
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
