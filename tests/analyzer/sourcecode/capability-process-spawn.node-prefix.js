// `node:child_process` is the documented specifier for the builtin and is
// what a modern codebase writes. Namespace import on purpose: the
// destructuring form is already covered by $js_spawn_destructure.
const cp = require('node:child_process');

module.exports = function run(command) {
  return cp.execSync(command, { encoding: 'utf8' });
};
