import json
import os

from guarddog.utils.package_info import get_package_info

dir_name = os.path.dirname(__file__)
with open(os.path.join(dir_name, "../../../guarddog/analyzer/metadata/resources/top_pypi_packages.json"), "r") as fd:
    raw = json.load(fd)
    PACKAGES = list(
        map(
            lambda x: x["project"],
            raw["rows"]
        )
    )
ALL_INFO = {}
i = 0
l = len(PACKAGES)
for name in PACKAGES:
    i += 1
    try:
        ALL_INFO[name] = get_package_info(name)
        print(name, "ok", i, "/", l)
    except Exception:
        print(name, "nok", i, "/", l)

with open(os.path.join(dir_name, 'all_info.json'), "w") as file:
    json.dump(ALL_INFO, file)
