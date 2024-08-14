from guarddog import ecosystems
from guarddog.analyzer.analyzer import SOURCECODE_RULES_PATH
from guarddog.analyzer.sourcecode import get_sourcecode_rules, YaraRule
import os
import yara  # type: ignore


def test_source_codde_analyzer_yararules():
    """
    This function tests all the yara rules in the soucecode folder
    """
    # any ecosystem will do, since YARA rules are not ecosystem specific
    yara_ruleset: set[str] = set(
        r.id for r in get_sourcecode_rules(ecosystems.ECOSYSTEM.PYPI, YaraRule)
    )
    
    SOURCECODE_RULES_TESTS_PATH = os.path.join(os.path.dirname(__file__))
    
    for rule_name in yara_ruleset:
        
        test_rule_path = {
            rule_name: os.path.join(SOURCECODE_RULES_PATH, f"{rule_name}.yar")
        }

        test_scan_rule = yara.compile(filepaths=test_rule_path)

        for root, _, files in os.walk(SOURCECODE_RULES_TESTS_PATH):
            for f in files:
                if not f.startswith(f"{rule_name}."):
                    continue

                # testing file against against rule
                assert test_scan_rule.match(os.path.join(root, f))
