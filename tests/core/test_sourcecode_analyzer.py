import json
from unittest.mock import mock_open, patch

import pytest

from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer

pypi_analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
npm_analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.NPM)


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
    assert len(result["errors"]) == 0


def test_source_code_analyzer_format():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)

    file_content = "line 1 content\nline 2 content\nline 3 content\nline 4 content\nline 5 content\n"
    expected_snippet = "line 2 content\nline 3 content\nline 4 content\n"
    # Sample output from semgrep
    sample_output = """
    {
        "version": "1.0.0",
        "results": [
            {
                "check_id": "guarddog.analyzer.sourcecode.sample_rule",
                "path": "/tmp/sample.py",
                "start": {
                    "line": 2
                },
                "end": {
                    "line": 4
                },
                "extra": {
                    "message": "message",
                    "metadata": {
                        "description": "description"
                    },
                    "severity": "WARNING"
                }
            }
        ],
        "errors": [],
        "paths": {
            "scanned": [
                "/tmp/sample.py"
            ]
        },
        "skipped_rules": []
    }
    """

    with patch("builtins.open", mock_open(read_data=file_content)):
        output = analyzer._format_semgrep_response(json.loads(sample_output))
    assert output.get("sample_rule")[0].get("code") == expected_snippet


def test_get_snippet_valid_range():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    path = "/tmp/sample.py"
    start_line = 2
    stop_line = 4
    file_content = "line 1 content\nline 2 content\nline 3 content\nline 4 content\nline 5 content\n"
    expected_snippet = "line 2 content\nline 3 content\nline 4 content\n"

    with patch("builtins.open", mock_open(read_data=file_content)):
        snippet = analyzer.get_snippet(path, start_line, stop_line)

    assert snippet == expected_snippet


def test_get_snippet_out_of_range():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    path = "/tmp/sample.py"
    start_line = 10
    stop_line = 20
    file_content = "line 1 content\nline 2 content\nline 3 content\nline 4 content\nline 5 content\n"
    expected_snippet = ""

    with patch("builtins.open", mock_open(read_data=file_content)):
        snippet = analyzer.get_snippet(path, start_line, stop_line)

    assert snippet == expected_snippet


def test_get_snippet_file_not_found():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    path = "/tmp/non_existent_file.py"
    start_line = 2
    stop_line = 4

    with patch("builtins.open", side_effect=FileNotFoundError):
        snippet = analyzer.get_snippet(path, start_line, stop_line)

    assert snippet == ""
