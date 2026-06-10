# FALSE POSITIVE: filelock OpenProcess liveness check (SYNCHRONIZE access only),
# not memory scraping.
def pid_alive(pid):
    SYNCHRONIZE = 0x00100000
    handle = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
    return bool(handle)
