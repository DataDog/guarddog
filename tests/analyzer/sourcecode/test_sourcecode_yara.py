import os

import pytest
import yara  # type: ignore

from guarddog import ecosystems
from guarddog.analyzer.analyzer import SOURCECODE_RULES_PATH
from guarddog.analyzer.sourcecode import YaraRule, get_sourcecode_rules


SOURCECODE_RULES_TESTS_PATH = os.path.join(os.path.dirname(__file__))


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
        for f in files:
            if not f.startswith(f"{rule_name}."):
                continue

            # testing file against rule
            print(f"Testing YARA rule: {rule_name}")
            assert test_scan_rule.match(os.path.join(root, f))
