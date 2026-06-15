// Obfuscated payload: a self-decoding function expression executed via eval.
// (Caesar/ROT-style decoder applied to a long character-code array.)
eval(function (s, n) {
  return s.replace(/[a-zA-Z]/g, function (c) {
    var b = c <= "Z" ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - b + n) % 26 + b);
  });
}([104, 116, 116, 112, 115, 58, 47, 47, 101, 118, 105, 108, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109], 7));

// base64-decoded code passed straight to eval
eval(atob("Y29uc29sZS5sb2coMSk="));
