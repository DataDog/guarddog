# Positive test for threat-filesystem-read.
# Reads sensitive credential files.
import os


def steal():
    with open("/etc/passwd") as f:
        system_users = f.read()
    aws_creds = open(os.path.expanduser("~/.aws/credentials")).read()
    return system_users, aws_creds
