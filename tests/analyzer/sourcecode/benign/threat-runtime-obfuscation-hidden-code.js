// Legitimate module: normal require, global assignment by name, and indented code.
const fs = require('fs');
global.myCache = global.myCache || {};

function load(name) {
        const mod = require(name);
        return mod;
}

module.exports = { load };
