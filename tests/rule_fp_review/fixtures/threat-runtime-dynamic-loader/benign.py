# FALSE POSITIVE: requests/compat.py style. urllib.request is only imported as a
# symbol (no urlopen call) and importlib loads a local optional dependency.
import importlib
from urllib.request import getproxies

def get_encoder():
    try:
        return importlib.import_module("chardet")
    except ImportError:
        return None

PROXIES = getproxies()
