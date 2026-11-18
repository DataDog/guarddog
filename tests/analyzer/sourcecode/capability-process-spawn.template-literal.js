// A template literal is the same specifier with a different quote. Nothing
// here is obfuscated; this is what the code looks like if someone reaches for
// backticks out of habit.
const cp = require(`child_process`);

module.exports = function run(command) {
  return cp.execSync(command, { encoding: 'utf8' });
};
