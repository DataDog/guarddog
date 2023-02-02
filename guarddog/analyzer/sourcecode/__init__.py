import os
import pathlib

import yaml
from yaml.loader import SafeLoader

from guarddog.ecosystems import ECOSYSTEM

current_dir = pathlib.Path(__file__).parent.resolve()
rule_file_names = list(
    filter(
        lambda x: x.endswith('yml'),
        os.listdir(current_dir)
    )
)

SOURCECODE_RULES = {
    ECOSYSTEM.PYPI: list(),
    ECOSYSTEM.NPM: list()
}  # type: dict[ECOSYSTEM, list[dict]]

for file_name in rule_file_names:
    with open(os.path.join(current_dir, file_name), "r") as fd:
        data = yaml.load(fd, Loader=SafeLoader)
        for rule in data["rules"]:
            for lang in rule["languages"]:
                match lang:
                    case "python":
                        SOURCECODE_RULES[ECOSYSTEM.PYPI].append(rule)
                    case "javascript" | "typescript" | "json":
                        SOURCECODE_RULES[ECOSYSTEM.NPM].append(rule)
