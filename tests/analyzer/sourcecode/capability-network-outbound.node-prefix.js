// `node:https` and `node:dns` resolve to the same builtins as `https` and
// `dns`. Kept to the bare require so the sample exercises the specifier and
// not one of the call-site strings.
const https = require('node:https');
const dns = require('node:dns');

module.exports = { https, dns };
