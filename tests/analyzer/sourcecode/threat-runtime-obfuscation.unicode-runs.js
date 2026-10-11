// Unicode-escape obfuscation must trigger threat.runtime.obfuscation: the
// payload is split into two long homoglyph runs glued together with
// repeated string concatenation.
var payload = "\u0041\u0042\u0043\u0044\u0045\u0046\u0047\u0048\u0049\u004A\u004B\u004C\u004D\u004E\u004F\u0050\u0051\u0052\u0053\u0054\u0055\u0056\u0057\u0058\u0059\u005A" +
  "\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A" +
  "\u002E" + "\u0073" + "\u0068" + "\u0021" + "\u0021";
eval(payload);
