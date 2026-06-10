import subprocess
# Recon: shelling out to system-info LOLBAS tools.
subprocess.check_output(["whoami"])
subprocess.run("hostname", shell=True)
