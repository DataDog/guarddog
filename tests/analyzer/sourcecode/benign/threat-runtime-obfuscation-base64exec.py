# Benign regression test for threat-runtime-obfuscation-base64exec.
# base64 decoding sits next to attribute-style method calls. Those are
# preceded by a dot, so only the bare builtins are treated as an execution
# sink. This file must not trigger.
import base64

decoded = base64.b64decode(blob)
prediction = model.eval(decoded)
cursor.exec(decoded)
