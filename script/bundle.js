console.log('');
console.log('****Bundling for Browser****');
console.log('');

var fs = require('fs');
var path = require('path');
var existsSync = fs.existsSync || path.existsSync;

var browserify = require('browserify');
//var browserifyShim = require('browserify-shim');
//var aliasify = require('aliasify');

var MODULE_HOME = path.join(__dirname, '../');
var INPUT       = path.join(MODULE_HOME, './weaveclient.js');
var OUTPUT      = path.join(MODULE_HOME, './weaveclient-bundle.js');

if (existsSync(OUTPUT)) {
  fs.unlinkSync(OUTPUT);
}

var bundle = browserify({standalone: 'weave'});

/*
var aliasifyConfig = {
  "util-deprecate": "chrome-util-deprecate"
};
bundle.transform(aliasify, aliasifyConfig);
*/

//omit builtin Node crypto and bigint modules
//bundle.exclude('crypto');
//bundle.exclude('bignum');
bundle.ignore('browserid-crypto/lib/algs/ds');

//omit Node xmlhttprequest compat module
bundle.exclude('xmlhttprequest');

bundle.add(INPUT);

bundle.bundle(function(err, buf) {
  if (err) {
    throw err;
  }
  fs.writeFileSync(OUTPUT, buf);
});
