var jam = {
    "packages": [
        {
            "name": "URIjs",
            "location": "jam/URIjs",
            "main": "src/URI.js"
        },
        {
            "name": "jquery",
            "location": "jam/jquery",
            "main": "dist/jquery.js"
        },
        {
            "name": "node-forge",
            "location": "jam/node-forge",
            "main": "js/forge.js"
        },
        {
            "name": "sprintf",
            "location": "jam/sprintf",
            "main": "js/sprintf.js"
        }
    ],
    "version": "0.2.17",
    "shim": {
        "sprintf": {
            "exports": "sprintf"
        }
    }
};

if (typeof require !== "undefined" && require.config) {
    require.config({
    "packages": [
        {
            "name": "URIjs",
            "location": "jam/URIjs",
            "main": "src/URI.js"
        },
        {
            "name": "jquery",
            "location": "jam/jquery",
            "main": "dist/jquery.js"
        },
        {
            "name": "node-forge",
            "location": "jam/node-forge",
            "main": "js/forge.js"
        },
        {
            "name": "sprintf",
            "location": "jam/sprintf",
            "main": "js/sprintf.js"
        }
    ],
    "shim": {
        "sprintf": {
            "exports": "sprintf"
        }
    }
});
}
else {
    var require = {
    "packages": [
        {
            "name": "URIjs",
            "location": "jam/URIjs",
            "main": "src/URI.js"
        },
        {
            "name": "jquery",
            "location": "jam/jquery",
            "main": "dist/jquery.js"
        },
        {
            "name": "node-forge",
            "location": "jam/node-forge",
            "main": "js/forge.js"
        },
        {
            "name": "sprintf",
            "location": "jam/sprintf",
            "main": "js/sprintf.js"
        }
    ],
    "shim": {
        "sprintf": {
            "exports": "sprintf"
        }
    }
};
}

if (typeof exports !== "undefined" && typeof module !== "undefined") {
    module.exports = jam;
}