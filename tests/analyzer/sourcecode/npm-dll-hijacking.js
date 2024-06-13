function f() {
  try {
    process.chdir("E:\\Games\\ALT1Games\\TwelveSky1");
    var injector = require("./build/release/injector");
    // ruleid: npm-dll-hijacking
    if (
      injector.executeInject(
        "TwelveSky.exe alt1games.twelvesky1:/test/test/0/18/0/2/1024/768",
        "E:\\Games\\ALT1Games\\TwelveSky1\\TSX_Client.dll"
      )
    ) {
      console.log("Process started and injected.");
    } else {
      console.log("Unable to execute and inject dll.");
    }
  } catch (err) {
    console.error("Exception Thrown!");
    console.error(err);
  }
}

function f() {
  // ruleid: npm-dll-hijacking
  execute("LD_PRELOAD=/tmp/lib", "/usr/bin/binary");
}

function f() {
  const fs = require("fs");

  const postData = "";

  // ruleid: npm-dll-hijacking
  fs.writeFileSync("/tmp/.so", "utf8", (err, data) => {
    if (err) {
      console.error(err);
      return;
    }
    postData = data;
  });
  
  spawn('/usr/bin/program', ['-lah'])
}
