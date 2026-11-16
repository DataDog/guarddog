// Positive test for threat-runtime-obfuscation-base64exec.
// Base64-decoded payload run through the bare eval() builtin.
const payload = atob(encoded);
eval(payload);
