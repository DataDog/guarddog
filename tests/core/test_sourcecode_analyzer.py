from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer
import pytest


pypi_analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
npm_analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
@pytest.mark.parametrize(
        "analyzer",
        [
            (pypi_analyzer),
            (npm_analyzer),
        ],
    )
def test_source_code_analyzer_ran_with_no_rules(analyzer: Analyzer):
    """
    Regression test for https://github.com/DataDog/guarddog/issues/161
    """
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)

    result = analyzer.analyze_sourcecode("/tmp", set())
    assert len(result['errors']) == 0
