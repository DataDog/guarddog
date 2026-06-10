import importlib
import urllib.request

def load_remote(name, url):
    payload = urllib.request.urlopen(url).read()
    exec(payload)
    return importlib.import_module(name)
