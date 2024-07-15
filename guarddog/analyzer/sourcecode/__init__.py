import os
import pathlib
from dataclasses import dataclass
from typing import Optional

import yaml
from yaml.loader import SafeLoader

from guarddog.ecosystems import ECOSYSTEM

current_dir = pathlib.Path(__file__).parent.resolve()


# These data class aim to reduce the spreading of the logic
# Instead of using the a dict as a structure and parse it difffently depending on the type
@dataclass
class SourceCodeRule:
    """
    Base class for source code rules
    """

    id: str
    file: str


@dataclass
class YaraRule(SourceCodeRule):
    """
    Yara rule just reimplements base
    """

    pass


@dataclass
class SempgrepRule(SourceCodeRule):
    """
    Semgrep rule are language specific
    Content of rule in yaml format is accessible through rule_content
    """

    description: str
    ecosystem: ECOSYSTEM
    rule_content: dict


def get_sourcecode_rules(
    ecosystem: ECOSYSTEM, kind: Optional[type] = None
) -> list[SourceCodeRule]:
    """
    This function returns the source code rules for a given ecosystem and kind.
    Args:
        ecosystem: The ecosystem to filter for if rules are ecosystem specific
        kind: The kind of rule to filter for
    """
    return [
        rule
        for rule in SOURCECODE_RULES
        if (getattr(rule, "ecosystem", ecosystem) == ecosystem)
        and (not kind or isinstance(rule, kind))
    ]


SOURCECODE_RULES: list[SourceCodeRule] = list()

semgrep_rule_file_names = list(
    filter(lambda x: x.endswith("yml"), os.listdir(current_dir))
)
# all yml files placed in the sourcecode directory are loaded as semgrep rules
# refer to README.md for more information
for file_name in semgrep_rule_file_names:
    with open(os.path.join(current_dir, file_name), "r") as fd:
        data = yaml.load(fd, Loader=SafeLoader)
        for rule in data["rules"]:
            for lang in rule["languages"]:
                ecosystem = None
                match lang:
                    case "python":
                        ecosystem = ECOSYSTEM.PYPI
                    case "javascript" | "typescript" | "json":
                        ecosystem = ECOSYSTEM.NPM
                    case _:
                        continue

                # avoids duplicates when multiple languages are supported by a rule
                if not [
                    r
                    for r in get_sourcecode_rules(ecosystem, SempgrepRule)
                    if (r.id == rule["id"])
                ]:
                    SOURCECODE_RULES.append(
                        SempgrepRule(
                            id=rule["id"],
                            ecosystem=ecosystem,
                            description=rule.get("metadata", {}).get("description", ""),
                            file=file_name,
                            rule_content=rule,
                        )
                    )

yara_rule_file_names = list(
    filter(lambda x: x.endswith("yar"), os.listdir(current_dir))
)
# all yar files placed in the sourcecode directory are loaded as YARA rules
# refer to README.md for more information
for file_name in yara_rule_file_names:
    SOURCECODE_RULES.append(YaraRule(id=pathlib.Path(file_name).stem, file=file_name))
