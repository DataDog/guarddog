import json

from guarddog.cli import _scan
from guarddog.ecosystems import ECOSYSTEM

rows = []
with open("guarddog/analyzer/metadata/resources/top_pypi_packages.json", "r") as fd:
    raw = json.load(fd)
    rows = raw["rows"]


for entry in rows:
    name = entry["project"]
    print(name)
    res = _scan(name, None, ["repository_integrity_missmatch"], [], "json", False, ECOSYSTEM.PYPI)


