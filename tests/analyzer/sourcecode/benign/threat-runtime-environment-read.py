# Legitimate code that should NOT trigger threat-runtime-environment-read

import os

# Reading non-credential config env vars
ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
tz_dir = os.getenv('PYTZDATA_TZDATADIR', '/usr/share/zoneinfo')
host = os.getenv('STATSD_HOST', 'localhost')
port = int(os.getenv('STATSD_PORT', '8125'))
debug = os.environ.get("DEBUG", "false")
log_level = os.getenv("LOG_LEVEL", "INFO")
home = os.environ.get("HOME")
path = os.environ["PATH"]
