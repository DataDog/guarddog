# Legitimate code that should NOT trigger threat-runtime-obfuscation-general

# Linter/AST tool referencing builtins as a string (not via getattr)
SPECIAL_BUILTINS = ("__builtins__",)
if mod not in (None, "builtins", "__builtins__"):
    pass

# Normal string with a few hex escapes (not obfuscation -- too short to match 10+ threshold)
header = b"\x89PNG\r\n\x1a\n"
magic = b"\x00\x00\x01\x00"
