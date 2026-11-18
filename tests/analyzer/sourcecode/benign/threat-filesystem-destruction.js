// Minified Emscripten runtime (pdf.js web worker) must NOT trigger
// threat.filesystem.destruction: the only 'rm' is inside the word
// 'terminated', and the '/home' string it gets paired with is elsewhere
// in the bundle (issue #903).
class ExitStatus { constructor(e) { this.message = `Program terminated with exit(${e})`; this.status = e; } }
var callRuntimeCallbacks = (e) => { for (; e.length > 0; ) e.shift()(a); };
var S = a.noExitRuntime;
var homeDir = getURL('/home');
