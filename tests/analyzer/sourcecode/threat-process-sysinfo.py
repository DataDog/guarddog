# Positive test for threat-process-sysinfo.
# Spawns the hostname/whoami LOLBAS commands to collect system info.
import os
import subprocess


def collect():
    host = os.popen("hostname").read()
    user = subprocess.run(["whoami"], capture_output=True)
    return host, user
