// Legitimate JavaScript that should NOT trigger threat-runtime-obfuscation-general

// Decoding bytes returned by an API into a string, spread over multiple lines.
// The fromCharCode argument is long but is a readable expression, not a list
// of numeric char codes (reported as a false positive in issue #793).
const checks = {
  "key starts with expected prefix": (msgs) =>
    String.fromCharCode(
      ...registry.deserialize({
        data: msgs[0].key,
        schemaType: SCHEMA_TYPE_BYTES,
      }),
    ).startsWith("test-id-"),
};

// Converting a typed array to a string, a common decoding idiom.
function bytesToString(bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
}

// Spread of a computed array with a long variable name.
const decoded = String.fromCharCode(...utf16CodeUnitsFromNetworkResponseBuffer);

// Legitimate unicode usage with a handful of explicit char codes.
const emoji = String.fromCharCode(0xd83d, 0xde00);
const arrows = String.fromCharCode(8592, 8593, 8594, 8595);
