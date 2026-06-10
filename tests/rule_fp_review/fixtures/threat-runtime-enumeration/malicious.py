import psutil
# Host enumeration: list every process and read the user database.
for proc in psutil.process_iter():
    print(proc.pid)
with open("/etc/passwd") as f:
    users = f.read()
