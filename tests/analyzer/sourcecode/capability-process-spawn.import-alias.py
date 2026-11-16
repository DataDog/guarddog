# Aliased imports hide the module name at the call site
import subprocess as _sp
from subprocess import Popen as _P

_sp.run(["id"], shell=False)
_P(["id"])
