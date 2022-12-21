import json

from guarddog.cli import _scan
from guarddog.ecosystems import ECOSYSTEM

rows = []
with open("guarddog/analyzer/metadata/resources/top_pypi_packages.json", "r") as fd:
    raw = json.load(fd)
    rows = raw["rows"]
rows = rows[0:1000]

with open("./results.txt", "w", buffering=1) as file:
    for entry in rows:
        name = entry["project"]
        if name == "idna":
            continue
        print("scanning", name)
        file.write(name + ": ")
        res = _scan(name, None, ["repository_integrity_missmatch"], [], "json", False, ECOSYSTEM.PYPI)
        file.write(res)
        file.write("\n")
        print("scanning", name, "done")


