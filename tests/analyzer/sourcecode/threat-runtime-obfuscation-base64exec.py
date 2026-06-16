# Positive test for threat-runtime-obfuscation-base64exec.
# base64-decoded payload passed to the bare exec() builtin.
import base64

exec(base64.b64decode("cHJpbnQoMSk="))
