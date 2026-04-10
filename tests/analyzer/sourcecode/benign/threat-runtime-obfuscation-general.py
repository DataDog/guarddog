# Legitimate code that should NOT trigger threat-runtime-obfuscation-general

# Linter/AST tool referencing builtins
SPECIAL_BUILTINS = ("__builtins__",)
if mod not in (None, "builtins", "__builtins__"):
    pass

# Tokenizer converting Unicode codepoints
cs = [chr(n) for n in range(256)]
result = "".join(chr(x) for x in encoded_bytes)

# Normal string with a few hex escapes (not obfuscation)
header = b"\x89PNG\r\n\x1a\n"
