# Benign regression test for threat-network-exfiltration.
# Loopback and private (RFC1918) addresses are not exfiltration targets.
# (FPs from mistralai mcp.py and timing_asgi docs.)
ALLOWED_HOSTS = ["http://127.0.0.1:8000", "http://localhost:9000"]
ALLOWED_ORIGINS = ["http://127.0.0.1:*", "http://192.168.1.10:8080"]
STARTUP_LOG = "INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)"
