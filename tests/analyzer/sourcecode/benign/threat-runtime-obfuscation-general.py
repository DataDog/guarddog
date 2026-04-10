# Legitimate code that should NOT trigger threat-runtime-obfuscation-general

# Linter/AST tool referencing builtins as a string (not via getattr)
SPECIAL_BUILTINS = ("__builtins__",)
if mod not in (None, "builtins", "__builtins__"):
    pass

# Normal string with a few hex escapes (not obfuscation -- below 30 threshold)
header = b"\x89PNG\r\n\x1a\n"
magic = b"\x00\x00\x01\x00"

# Crypto test vectors with hex escapes (below 30 consecutive)
digest = b"\x02\x82\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Tokenizer converting codepoints (chr loop)
cs = [chr(n) for n in range(256)]
result = "".join(chr(x) for x in encoded_bytes)
