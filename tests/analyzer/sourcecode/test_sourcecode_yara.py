import os

import pytest
import yara  # type: ignore

from guarddog import ecosystems
from guarddog.analyzer.analyzer import SOURCECODE_RULES_PATH
from guarddog.analyzer.sourcecode import YaraRule, get_sourcecode_rules


SOURCECODE_RULES_TESTS_PATH = os.path.join(os.path.dirname(__file__))
BENIGN_TESTS_PATH = os.path.join(SOURCECODE_RULES_TESTS_PATH, "benign")


# any ecosystem will do, since YARA rules are not ecosystem specific
yara_ruleset: set[str] = set(
    r.id for r in get_sourcecode_rules(ecosystems.ECOSYSTEM.PYPI, YaraRule)
)


@pytest.mark.parametrize("rule_name", yara_ruleset)
def test_source_codde_analyzer_yara_compile(rule_name: str):
    """
    This function compiles all yara rules in the soucecode folder
    """

    test_rule_path = {
        rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
    }

    assert yara.compile(filepaths=test_rule_path)


@pytest.mark.parametrize("rule_name", yara_ruleset)
def test_source_codde_analyzer_yara_exec(rule_name: str):
    """
    This function tests all the yara rules in the soucecode folder
    """

    SOURCECODE_RULES_TESTS_PATH = os.path.join(os.path.dirname(__file__))

    test_rule_path = {
        rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
    }

    test_scan_rule = yara.compile(filepaths=test_rule_path)

    for root, _, files in os.walk(SOURCECODE_RULES_TESTS_PATH):
        if "benign" in root:
            continue
        for f in files:
            if not f.startswith(f"{rule_name}."):
                continue

            # testing file against rule
            print(f"Testing YARA rule: {rule_name}")
            assert test_scan_rule.match(os.path.join(root, f))


# Collect rules that have benign test files
benign_test_rules: list[str] = []
if os.path.isdir(BENIGN_TESTS_PATH):
    for f in os.listdir(BENIGN_TESTS_PATH):
        rule_name = os.path.splitext(f)[0]
        if rule_name in yara_ruleset:
            benign_test_rules.append(rule_name)


@pytest.mark.parametrize("rule_name", sorted(benign_test_rules))
def test_sourcecode_analyzer_yara_no_false_positives(rule_name: str):
    """
    Verify that rules do NOT match benign/legitimate code samples.
    Each file in tests/analyzer/sourcecode/benign/{rule_name}.* contains
    code patterns that previously caused false positives.
    """
    test_rule_path = {
        rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
    }
    compiled_rule = yara.compile(filepaths=test_rule_path)

    for f in os.listdir(BENIGN_TESTS_PATH):
        if not f.startswith(f"{rule_name}."):
            continue
        benign_file = os.path.join(BENIGN_TESTS_PATH, f)
        matches = compiled_rule.match(benign_file)
        assert not matches, (
            f"Rule {rule_name} should NOT match benign file {f}, "
            f"but matched: {[m.rule for m in matches]}"
        )
