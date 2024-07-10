import os
import pathlib

import yaml
from yaml.loader import SafeLoader

from guarddog.ecosystems import ECOSYSTEM

current_dir = pathlib.Path(__file__).parent.resolve()
semgrep_rule_file_names = list(
    filter(
        lambda x: x.endswith('yml'),
        os.listdir(current_dir)
    )
)

SEMGREP_SOURCECODE_RULES = {
    ECOSYSTEM.PYPI: list(),
    ECOSYSTEM.NPM: list(),
}  # type: dict[ECOSYSTEM, list[dict]]

# all yml files placed in the sourcecode directory are loaded as semgrep rules
# refer to README.md for more information
for file_name in semgrep_rule_file_names:
    with open(os.path.join(current_dir, file_name), "r") as fd:
        data = yaml.load(fd, Loader=SafeLoader)
        for rule in data["rules"]:
            for lang in rule["languages"]:
                match lang:
                    case "python":
                        if rule not in SEMGREP_SOURCECODE_RULES[ECOSYSTEM.PYPI]:
                            SEMGREP_SOURCECODE_RULES[ECOSYSTEM.PYPI].append(rule)
                    case "javascript" | "typescript" | "json":
                        if rule not in SEMGREP_SOURCECODE_RULES[ECOSYSTEM.NPM]:
                            SEMGREP_SOURCECODE_RULES[ECOSYSTEM.NPM].append(rule)

yara_rule_file_names = list(
    filter(
        lambda x: x.endswith('yar'),
        os.listdir(current_dir)
    )
)

YARA_RULES: set[str] = set()

# all yar files placed in the sourcecode directory are loaded as YARA rules
# refer to README.md for more information
for file_name in yara_rule_file_names:
    YARA_RULES.add(pathlib.Path(file_name).stem)


def get_sourcecode_rules(ecosystem: ECOSYSTEM) -> set:
    return {r["id"] for r in SEMGREP_SOURCECODE_RULES[ecosystem]} | YARA_RULES
