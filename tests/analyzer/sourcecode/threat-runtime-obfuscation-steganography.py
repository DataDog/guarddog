# Positive test for threat-runtime-obfuscation-steganography.
# Hidden payload recovered from a PNG then run through the bare exec() builtin.
from stegano import lsb

payload = lsb.reveal("cover.png")
exec(payload)
