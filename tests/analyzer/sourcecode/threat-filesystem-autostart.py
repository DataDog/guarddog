# Positive test for threat-filesystem-autostart.
# Persistence by appending a payload to the user's shell startup file.
import os


def persist(payload):
    rc = os.path.expanduser("~/.bashrc")
    with open(rc, "a") as f:
        f.write(payload)


# Persistence by writing a .pth into site-packages: site.py executes lines
# starting with "import" at every interpreter startup, so the payload runs at
# every future Python start.
import site


def persist_pth(payload):
    target = site.getsitepackages()[0] + "/evil.pth"
    with open(target, "w") as f:
        f.write(payload)
