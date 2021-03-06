/*
 * Copyright 2014 Gerry Healy <nickel_chrome@mac.com>
 *
 *  Weave helper objects
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

// Export sub-modules


exports.account = {};
exports.account.fxa = require('./lib/account/fxa');
exports.account.legacy = require('./lib/account/legacy');

exports.client = require('./lib/weave-client');
exports.crypto = require('./lib/weave-crypto');
exports.storage = require('./lib/weave-storage');
exports.util = require('./lib/weave-util');
exports.error = require('./lib/weave-error');

module.exports = exports;
