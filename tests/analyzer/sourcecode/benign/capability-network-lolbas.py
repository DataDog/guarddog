# Legitimate code that should NOT trigger capability-network-lolbas

# Documentation mentioning curl
"""
Submitting bulk requests with cURL:
    curl https://api.example.com/data
"""

# Package names containing "curl"
DEPENDENCIES = ["curl-cffi", "pycurl"]

# US state abbreviations
LOCATIONS = {
    '1704216': {'en': 'Salisbury, NC'},
    '1704217': {'en': 'Charlotte, NC'},
}

# CSS class names
STYLES = {
    "nc": "#000000",  # class: 'nc' - Name.Class
}

# Telnet in documentation context
PROTOCOLS = ["http", "https", "telnet", "ftp"]
