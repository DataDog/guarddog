# FALSE POSITIVE: legitimate URLs. A suspicious-TLD substring inside a longer
# domain (gap-system.org) and non-routable IPs (loopback, cloud metadata) are
# not exfiltration destinations.
HOMEPAGE = "https://www.gap-system.org/"
LOCAL_DEBUG = "http://127.0.0.1:8080/debug"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
