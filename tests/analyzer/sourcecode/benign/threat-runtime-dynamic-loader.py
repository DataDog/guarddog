# Legit: dynamic import of an optional dependency plus an unrelated HTTP call.
# The downloaded data is never exec'd, so this must NOT trip the dynamic loader.
import importlib
import requests


def get_plugin(name):
    return importlib.import_module(name)


def fetch_version(url):
    return requests.get(url, timeout=1).json()
