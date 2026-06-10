// FALSE POSITIVE: a CLI that imports child_process (to spawn a local build) and
// uses fetch (to read a registry index). Neither downloads code that is executed.
const { spawn } = require("child_process");

export async function fetchVersions() {
  const res = await fetch("https://registry.example.com/versions.json");
  return res.json();
}

export function build(args) {
  return spawn("node", args);
}
