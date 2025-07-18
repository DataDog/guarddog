import os
import re
import pathlib
from dataclasses import dataclass
from typing import Optional, Iterable

import yaml
from yaml.loader import SafeLoader

from guarddog.ecosystems import ECOSYSTEM

current_dir = pathlib.Path(__file__).parent.resolve()


# These data class aim to reduce the spreading of the logic
# Instead of using the a dict as a structure and parse it difffently
# depending on the type
@dataclass
class SourceCodeRule:
    """
    Base class for source code rules
    """
    id: str
    file: str
    description: str
    ecosystem: Optional[ECOSYSTEM]  # None means "any ecosystem"


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
    rule_content: dict


def get_sourcecode_rules(
        ecosystem: ECOSYSTEM, kind: Optional[type] = None) -> Iterable[SourceCodeRule]:
    """
    This function returns the source code rules for a given ecosystem and kind.
    Args:
        ecosystem: The ecosystem to filter for if rules are ecosystem specific
        kind: The kind of rule to filter for
    """
    for rule in SOURCECODE_RULES:
        if kind and not isinstance(rule, kind):
            continue
        # Include rules that match the specific ecosystem OR rules that apply to any ecosystem (None)
        if rule.ecosystem is not None and rule.ecosystem != ecosystem:
            continue
        yield rule


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
                ecosystems = set()
                match lang:
                    case "python":
                        ecosystems.add(ECOSYSTEM.PYPI)
                    case "javascript" | "typescript" | "json":
                        ecosystems.add(ECOSYSTEM.NPM)
                        ecosystems.add(ECOSYSTEM.GITHUB_ACTION)
                        ecosystems.add(ECOSYSTEM.EXTENSION)
                    case "go":
                        ecosystems.add(ECOSYSTEM.GO)
                    case _:
                        continue

                for ecosystem in ecosystems:
                    # avoids duplicates when multiple languages are supported
                    # by a rule
                    if not next(
                        filter(
                            lambda r: r.id == rule["id"],
                            get_sourcecode_rules(ecosystem, SempgrepRule),
                        ),
                        None,
                    ):
                        SOURCECODE_RULES.append(
                            SempgrepRule(
                                id=rule["id"],
                                ecosystem=ecosystem,
                                description=rule.get("metadata", {}).get("description", ""),
                                file=file_name,
                                rule_content=rule,
                            ))

yara_rule_file_names = list(
    filter(lambda x: x.endswith("yar"), os.listdir(current_dir))
)
# all yar files placed in the sourcecode directory are loaded as YARA rules
# refer to README.md for more information
for file_name in yara_rule_file_names:
    rule_id = pathlib.Path(file_name).stem
    description_regex = fr'\s*rule\s+{rule_id}[^}}]+meta:[^}}]+description\s*=\s*\"(.+?)\"'

    # Determine ecosystem based on filename prefix
    rule_ecosystem: Optional[ECOSYSTEM]
    if file_name.startswith("extension_"):
        rule_ecosystem = ECOSYSTEM.EXTENSION
    else:
        # If no specific ecosystem prefix, apply to any ecosystem
        rule_ecosystem = None

    with open(os.path.join(current_dir, file_name), "r") as fd:
        match = re.search(description_regex, fd.read())
        rule_description = ""
        if match:
            rule_description = match.group(1)

        SOURCECODE_RULES.append(YaraRule(
            id=rule_id,
            file=file_name,
            description=rule_description,
            ecosystem=rule_ecosystem
        ))
