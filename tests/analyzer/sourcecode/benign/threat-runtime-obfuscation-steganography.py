# Benign regression test for threat-runtime-obfuscation-steganography.
# A stego library reading a PNG, but the only call named exec is a method call
# (node.exec), preceded by a dot. The bare builtin is what matters, so this
# must not trigger.
from stegano import lsb

img = lsb.reveal("cover.png")
node.exec(payload)
