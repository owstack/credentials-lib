'use strict';

var credentialsLib = {};

// Module information
credentialsLib.version = 'v' + require('./package.json').version;

// Main credentials library
credentialsLib.Common = require('./lib/common');
credentialsLib.Credentials = require('./lib/credentials.js');

module.exports = credentialsLib;
