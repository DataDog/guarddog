// core-js whitespace/charset tables: unicode escape runs glued with
// string concatenation, exactly as the pdfjs-dist legacy bundle ships
// them (legacy/web/pdf_viewer.mjs, issue #903). Charset tables are data,
// not obfuscation, and must NOT trigger threat.runtime.obfuscation.
// a string of all valid unicode whitespaces
module.exports = '\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000\u2001\u2002' +
  '\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';
var emojiTable = '\u1F600\u1F603\u1F604\u1F605\u1F606\u1F609\u1F60A\u1F60D\u1F60E\u1F60F\u1F612' + '';
var digitTable = '\u0030\u0031\u0032\u0033\u0034\u0035\u0036\u0037\u0038\u0039\u0041' + '';
var mathOps = '\u002B\u002D\u002A\u002F\u003D\u003C\u003E\u0021\u003F\u0026\u007C' + '';
var banner = 'whitespace-aware' + ' parser';
var notice = 'charset' + ' tables';
