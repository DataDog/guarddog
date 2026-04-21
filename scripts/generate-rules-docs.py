import sys
from collections import OrderedDict
from fnmatch import fnmatch

from guarddog.analyzer.sourcecode import get_sourcecode_rules
from guarddog.analyzer.metadata import get_metadata_detectors
from guarddog.ecosystems import ECOSYSTEM, get_friendly_name

START_MARKER = "<!-- BEGIN_RULE_LIST -->\n"
END_MARKER = "<!-- END_RULE_LIST -->\n"

# Map file extensions/patterns to ecosystems they belong to
_EXTENSION_TO_ECOSYSTEMS = {
    ".py": {ECOSYSTEM.PYPI},
    ".pyx": {ECOSYSTEM.PYPI},
    ".pyi": {ECOSYSTEM.PYPI},
    ".js": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".ts": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".jsx": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".tsx": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".mjs": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".cjs": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    ".go": {ECOSYSTEM.GO},
    ".rb": {ECOSYSTEM.RUBYGEMS},
    ".gemspec": {ECOSYSTEM.RUBYGEMS},
}

# Filename patterns (not just extensions) that map to ecosystems
_FILENAME_TO_ECOSYSTEMS = {
    "package.json": {ECOSYSTEM.NPM, ECOSYSTEM.GITHUB_ACTION, ECOSYSTEM.EXTENSION},
    "setup.py": {ECOSYSTEM.PYPI},
    "Rakefile": {ECOSYSTEM.RUBYGEMS},
    "extconf.rb": {ECOSYSTEM.RUBYGEMS},
}


def _ecosystems_from_path_include(path_include: str | None) -> set[ECOSYSTEM]:
    """Derive which ecosystems a YARA rule applies to based on its path_include patterns."""
    if not path_include:
        # No filter means all ecosystems
        return set(ECOSYSTEM)

    ecosystems: set[ECOSYSTEM] = set()
    for pattern in path_include.split(","):
        pattern = pattern.strip()
        # Check by extension: extract ext from patterns like "*.py" or "*/setup.py"
        for ext, ecos in _EXTENSION_TO_ECOSYSTEMS.items():
            if pattern.endswith(ext):
                ecosystems.update(ecos)
        # Check by filename pattern
        for fname, ecos in _FILENAME_TO_ECOSYSTEMS.items():
            if fnmatch(fname, pattern.lstrip("*/")):
                ecosystems.update(ecos)

    return ecosystems


def _make_eco_header(eco_names: list[str]) -> tuple[str, str]:
    header = ""
    separator = ""
    for name in eco_names:
        header += f" **{name}** |"
        separator += ":---:|"
    return header, separator


def _make_eco_cols(ecosystems: list[ECOSYSTEM], rule_ecosystems: set[ECOSYSTEM]) -> str:
    return "".join(
        " :white_check_mark: |" if eco in rule_ecosystems else " |"
        for eco in ecosystems
    )


def generate_docs() -> str:
    ecosystems = list(ECOSYSTEM)
    eco_names = [get_friendly_name(e) for e in ecosystems]
    eco_header, eco_sep = _make_eco_header(eco_names)

    # --- Collect source code rules (deduplicated) ---
    capabilities: OrderedDict[str, dict] = OrderedDict()
    threats: OrderedDict[str, dict] = OrderedDict()

    for eco in ecosystems:
        for rule in get_sourcecode_rules(eco):
            if rule.id in capabilities or rule.id in threats:
                continue
            entry = {
                "identifies": rule.identifies or "",
                "description": (rule.description or "").replace("\n", ""),
                "severity": rule.severity or "",
                "ecosystems": _ecosystems_from_path_include(rule.path_include),
            }
            identifies = rule.identifies or ""
            if identifies.startswith("capability."):
                capabilities[rule.id] = entry
            else:
                threats[rule.id] = entry

    # --- Capability rules table ---
    output = "## Capability rules\n\n"
    output += (
        f"| **Rule** | **Identifies** | **Description** | **Severity** |{eco_header}\n"
    )
    output += (
        f"|:---------|:---------------|:----------------|:------------:|{eco_sep}\n"
    )
    for rule_id, info in capabilities.items():
        eco_cols = _make_eco_cols(ecosystems, info["ecosystems"])
        output += (
            f"| {rule_id} | `{info['identifies']}` | {info['description']} "
            f"| {info['severity']} |{eco_cols}\n"
        )

    # --- Threat rules table (source code) ---
    output += "\n## Threat rules (source code)\n\n"
    output += (
        f"| **Rule** | **Identifies** | **Description** | **Severity** |{eco_header}\n"
    )
    output += (
        f"|:---------|:---------------|:----------------|:------------:|{eco_sep}\n"
    )
    for rule_id, info in threats.items():
        eco_cols = _make_eco_cols(ecosystems, info["ecosystems"])
        output += (
            f"| {rule_id} | `{info['identifies']}` | {info['description']} "
            f"| {info['severity']} |{eco_cols}\n"
        )

    # --- Threat rules (metadata) ---
    md_rules: OrderedDict[str, dict] = OrderedDict()
    for eco in ecosystems:
        for rule_name, detector in get_metadata_detectors(eco).items():
            if rule_name not in md_rules:
                md_rules[rule_name] = {
                    "identifies": detector.identifies or "",
                    "description": (detector.get_description() or "").replace("\n", ""),
                    "severity": detector.severity or "",
                    "mitre": detector.mitre_tactics or "",
                    "ecosystems": set(),
                }
            md_rules[rule_name]["ecosystems"].add(eco)

    output += "\n## Threat rules (metadata)\n\n"
    output += f"| **Rule** | **Identifies** | **Description** | **Severity** | **MITRE Tactic** |{eco_header}\n"
    output += f"|:---------|:---------------|:----------------|:------------:|:----------------:|{eco_sep}\n"
    for rule_name, info in md_rules.items():
        eco_cols = _make_eco_cols(ecosystems, info["ecosystems"])
        output += (
            f"| {rule_name} | `{info['identifies']}` | {info['description']} "
            f"| {info['severity']} | {info['mitre']} |{eco_cols}\n"
        )

    output += "\n"
    return output


def inject_docs(file_name: str, new_docs: str):
    with open(file_name, "r") as f:
        contents = "".join(f.readlines())

    start = end = 0
    try:
        start = contents.index(START_MARKER)
        end = contents.index(END_MARKER)
    except ValueError:
        sys.stderr.write(
            f"Unable to inject docs in {file_name}, missing start or end marker"
        )
        exit(1)

    before = contents[0:start]
    after = contents[end:]

    new_contents = (
        before + START_MARKER + new_docs + after
    )  # 'after' already contains the end marker
    with open(file_name, "w") as f:
        f.write(new_contents)
    print(f"Wrote autogenerated docs to {file_name}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(generate_docs())
    elif len(sys.argv) == 2:
        file = sys.argv[1]
        print(f"Generating docs and injecting into {file}")
        inject_docs(file, generate_docs())
