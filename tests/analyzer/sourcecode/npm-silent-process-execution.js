// TEST CASE: Malware sample
var spawn = require('child_process').spawn;
// ruleid: npm-silent-process-execution
spawn('node', ['svc.js',process.pid], {
    detached: true,
    stdio: 'ignore' // piping all stdio to /dev/null
}).unref();


// TEST CASE: Using spawnSync instead of spawn
var spawnSync = require('child_process').spawnSync;
// ruleid: npm-silent-process-execution
spawnSync('node', ['svc.js',process.pid], {
    detached: true,
    stdio: 'ignore' // piping all stdio to /dev/null
}).unref();

// TEST CASE: Not importing only 'spawn'
var process = require('child_process');
// ruleid: npm-silent-process-execution
process.spawn('node', ['svc.js',process.pid], {
    detached: true,
    stdio: 'ignore' // piping all stdio to /dev/null
}).unref();


// TEST CASE: with additional parameters
var process = require('child_process');
// ruleid: npm-silent-process-execution
process.spawn('node', ['svc.js',process.pid], {
    detached: true,
    stdio: 'ignore', // piping all stdio to /dev/null
    env: {}
}).unref();


// TEST CASE: Spawning a process without silencing the output
// ok: npm-silent-process-execution
spawn('ls', ['-lah'])
