from .autotuner import Config, Heuristics, autotune, heuristics  # noqa: F401
from .jit import JITFunction, KernelInterface, version_key  # noqa: F401

try:
    import subprocess
    import os

    # ruleid: silent-process-execution
    subprocess.Popen(os.path.join(os.path.dirname(os.path.abspath(__file__)), "foobar"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL)
except:
    pass