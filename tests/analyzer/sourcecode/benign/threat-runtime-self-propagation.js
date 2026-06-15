// Legitimate release helper: bumps the version in package.json and runs the
// test suite via child_process. It rewrites the manifest and spawns processes,
// but never invokes a registry publish, so it must NOT match the worm rule.
const fs = require("fs");
const { execSync } = require("child_process");

function bumpVersion(nextVersion) {
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf-8"));
  pkg.version = nextVersion;
  fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2));

  execSync("npm run build", { stdio: "inherit" });
  execSync("npm test", { stdio: "inherit" });
}

module.exports = { bumpVersion };
