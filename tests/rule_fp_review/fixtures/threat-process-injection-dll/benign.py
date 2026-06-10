# FALSE POSITIVE: filelock uses kernel32 only to check whether the lock-holding
# process is still alive (OpenProcess + CloseHandle). No injection.
import ctypes
def pid_exists(pid):
    SYNCHRONIZE = 0x00100000
    h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
    if h:
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    return False
