// Positive test for threat-runtime-obfuscation-steganography.
// Hidden payload recovered from a PNG then run through the bare eval() builtin.
const hidden = stego.decode('cover.png');
eval(hidden);
