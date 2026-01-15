import os
import re
import pathlib
from dataclasses import dataclass
from typing import Optional, Iterable, List

import yaml
from yaml.loader import SafeLoader

from guarddog.ecosystems import ECOSYSTEM

current_dir = pathlib.Path(__file__).parent.resolve()

EXTENSION_YARA_PREFIX = "extension_"

# These data class aim to reduce the spreading of the logic
# Instead of using the a dict as a structure and parse it difffently
# depending on the type


@dataclass
class SourceCodeRule:
    """
    Base class for source code rules

    Attributes:
        id: Rule identifier
        file: Rule filename
        description: Human-readable description
        ecosystem: Target ecosystem (None = any)
        identifies: What this rule detects (e.g., "threat.network.outbound")
        severity: Impact level (low/medium/high)
        mitre_tactics: List of MITRE ATT&CK tactics
        specificity: Pattern specificity - how specific to malware vs legitimate code (low/medium/high)
        sophistication: Technique advancement (low/medium/high)
        max_hits: Maximum number of risks to form from this rule per file (None = unlimited)
    """

    id: str
    file: str
    description: str
    ecosystem: Optional[ECOSYSTEM]  # None means "any ecosystem"

    # New risk-based metadata
    identifies: Optional[str] = None
    severity: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    specificity: Optional[str] = None
    sophistication: Optional[str] = None
    max_hits: Optional[int] = (
        None  # None = unlimited, capabilities typically 1, threats typically 5
    )
    path_include: Optional[str] = None  # Glob patterns: "*/package.json,*/setup.py"


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

    rule_content: Optional[dict] = None


def get_sourcecode_rules(
    ecosystem: ECOSYSTEM, kind: Optional[type] = None
) -> Iterable[SourceCodeRule]:
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
            metadata = rule.get("metadata", {})

            # Extract risk-based metadata from Semgrep rules
            identifies = metadata.get("identifies")
            severity = metadata.get("severity")
            mitre_tactics = metadata.get("mitre_tactics", [])  # Default to empty list
            specificity = metadata.get("specificity")
            sophistication = metadata.get("sophistication")
            max_hits = metadata.get("max_hits")  # None = unlimited

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
                    case "ruby":
                        ecosystems.add(ECOSYSTEM.RUBYGEMS)
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
                                description=metadata.get("description", ""),
                                file=file_name,
                                rule_content=rule,
                                identifies=identifies,
                                severity=severity,
                                mitre_tactics=mitre_tactics,
                                specificity=specificity,
                                sophistication=sophistication,
                                max_hits=max_hits,
                            )
                        )

yara_rule_file_names = list(
    filter(lambda x: x.endswith("yar"), os.listdir(current_dir))
)
# all yar files placed in the sourcecode directory are loaded as YARA rules
# refer to README.md for more information
for file_name in yara_rule_file_names:
    rule_id = pathlib.Path(file_name).stem

    # Determine ecosystem based on filename prefix
    rule_ecosystem: Optional[ECOSYSTEM] = (
        ECOSYSTEM.EXTENSION if file_name.startswith(EXTENSION_YARA_PREFIX) else None
    )

    with open(os.path.join(current_dir, file_name), "r") as fd:
        content = fd.read()

        # Extract description
        description_match = re.search(
            rf"\s*rule\s+{rule_id}[^}}]+meta:[^}}]+description\s*=\s*\"(.+?)\"", content
        )
        rule_description = description_match.group(1) if description_match else ""

        # Extract new risk-based metadata fields
        identifies_match = re.search(r"identifies\s*=\s*\"(.+?)\"", content)
        identifies = identifies_match.group(1) if identifies_match else None

        severity_match = re.search(r"severity\s*=\s*\"(.+?)\"", content)
        severity = severity_match.group(1) if severity_match else None

        specificity_match = re.search(r"specificity\s*=\s*\"(.+?)\"", content)
        specificity = specificity_match.group(1) if specificity_match else None

        sophistication_match = re.search(r"sophistication\s*=\s*\"(.+?)\"", content)
        sophistication = sophistication_match.group(1) if sophistication_match else None

        # Extract MITRE tactics (comma-separated string format)
        # For capabilities without tactics, default to empty list
        mitre_tactics = []
        tactics_match = re.search(r"mitre_tactics\s*=\s*\"(.+?)\"", content)
        if tactics_match:
            tactics_str = tactics_match.group(1)
            # Parse comma-separated values
            if tactics_str.strip():
                mitre_tactics = [t.strip() for t in tactics_str.split(",") if t.strip()]

        # Extract max_hits (integer or None)
        max_hits = None
        max_hits_match = re.search(r"max_hits\s*=\s*(\d+)", content)
        if max_hits_match:
            max_hits = int(max_hits_match.group(1))

        # Extract path_include (glob patterns)
        path_include_match = re.search(r"path_include\s*=\s*\"(.+?)\"", content)
        path_include = path_include_match.group(1) if path_include_match else None

        SOURCECODE_RULES.append(
            YaraRule(
                id=rule_id,
                file=file_name,
                description=rule_description,
                ecosystem=rule_ecosystem,
                identifies=identifies,
                severity=severity,
                mitre_tactics=mitre_tactics,
                specificity=specificity,
                sophistication=sophistication,
                max_hits=max_hits,
                path_include=path_include,
            )
        )
