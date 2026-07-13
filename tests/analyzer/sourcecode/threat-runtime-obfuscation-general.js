// Obfuscated JavaScript patterns that MUST trigger threat-runtime-obfuscation-general

// String built from a long list of numeric char codes (decimal)
var cmd = String.fromCharCode(99, 117, 114, 108, 32, 104, 116, 116, 112, 58, 47, 47, 101, 118, 105, 108);

// Same technique with hex literals, spread across lines
var payload = String.fromCharCode(
  0x63, 0x75, 0x72, 0x6c,
  0x20, 0x68, 0x74, 0x74,
  0x70, 0x3a, 0x2f, 0x2f
);
