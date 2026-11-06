# Aliased imports hide the module name at the call site
import requests as _r
import urllib.request as _u
from requests import post as _post

_r.get("https://example.com/collect")
_u.urlopen("https://example.com/x")
_post("https://example.com/collect", data={})
