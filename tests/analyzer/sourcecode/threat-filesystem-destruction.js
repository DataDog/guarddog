// Wiping a user's home directory must trigger threat.filesystem.destruction
// (the $wipe_home/$wipe_users arms previously had no positive fixture).
const { exec } = require("child_process");
exec('rm -rf '/home/deployer');
exec('rm -rf '/Users/bob');
