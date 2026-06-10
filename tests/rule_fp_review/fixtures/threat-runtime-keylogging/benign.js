// FALSE POSITIVE: React reads its devtools global hook. The substring
// "GLOBAL_HOOK" trips $global_hook but has nothing to do with keylogging.
const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
if (hook) {
  hook.inject(internals);
}
