import os
from time import sleep

from guarddog.utils.package_info import get_package_info
import json

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
for name in PACKAGES:
    try:
        ALL_INFO[name] = get_package_info(name)
        print(name, "ok")
    except Exception:
        print(name, "nok")
    sleep(1)

with open(os.path.join(dir_name, 'all_info.json'), "w") as file:
    json.dump(ALL_INFO, file)
