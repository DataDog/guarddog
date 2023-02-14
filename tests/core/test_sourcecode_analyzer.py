from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer


def test_source_code_analyzer_ran_with_no_rules():
    """
    Regression test for https://github.com/DataDog/guarddog/issues/161
    """
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)

    result = analyzer.analyze_sourcecode("/tmp", set())
    assert len(result['errors']) == 0
