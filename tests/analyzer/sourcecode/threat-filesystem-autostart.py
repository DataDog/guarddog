# Positive test for threat-filesystem-autostart.
# Persistence by appending a payload to the user's shell startup file.
import os


def persist(payload):
    rc = os.path.expanduser("~/.bashrc")
    with open(rc, "a") as f:
        f.write(payload)
