# Positive test for threat-process-sysinfo.
# Spawns the hostname/whoami LOLBAS commands to collect system info.
import os
import subprocess


def collect():
    host = os.popen("hostname").read()
    user = subprocess.run(["whoami"], capture_output=True)
    return host, user


# Detected by command context (flags, absolute path) regardless of the host
# language, not just by a Python-specific exec wrapper.
def collect_via_command():
    os.system("whoami /all")
    subprocess.run("hostname -I", shell=True)
    return "/usr/bin/whoami"
