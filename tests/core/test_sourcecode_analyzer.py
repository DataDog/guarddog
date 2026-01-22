import json
import tempfile
import os
from unittest.mock import mock_open, patch

import pytest

from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import LANGUAGE

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


# Comment filtering tests


@pytest.mark.parametrize(
    "file_path,expected",
    [
        ("/tmp/test.py", LANGUAGE.PYTHON),
        ("/tmp/test.pyx", LANGUAGE.PYTHON),
        ("/tmp/test.pyi", LANGUAGE.PYTHON),
        ("/tmp/test.js", LANGUAGE.JAVASCRIPT),
        ("/tmp/test.jsx", LANGUAGE.JAVASCRIPT),
        ("/tmp/test.mjs", LANGUAGE.JAVASCRIPT),
        ("/tmp/test.cjs", LANGUAGE.JAVASCRIPT),
        ("/tmp/test.ts", LANGUAGE.TYPESCRIPT),
        ("/tmp/test.tsx", LANGUAGE.TYPESCRIPT),
        ("/tmp/test.go", LANGUAGE.GO),
        ("/tmp/test.rb", LANGUAGE.RUBY),
        ("/tmp/test.java", None),
        ("/tmp/test.cpp", None),
    ],
)
def test_detect_language(file_path, expected):
    """Test language detection from file extensions."""
    assert Analyzer._detect_language(file_path) == expected


@pytest.mark.parametrize(
    "suffix,language",
    [
        ('.js', LANGUAGE.JAVASCRIPT),
        ('.ts', LANGUAGE.TYPESCRIPT),
        ('.go', LANGUAGE.GO),
    ]
)
def test_is_in_multiline_comment_cstyle_inside(suffix, language):
    """Test detection of match inside C-style multi-line comment."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("const x = 1;\n")
        f.write("/* This is a comment\n")
        f.write("with pattern here\n")
        f.write("*/\n")
        f.write("const y = 2;\n")
        f.flush()

        # Byte offset at "pattern" which is inside the comment
        byte_offset = len("const x = 1;\n/* This is a comment\nwith ".encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, language, byte_offset=byte_offset) is True
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,language",
    [
        ('.js', LANGUAGE.JAVASCRIPT),
        ('.ts', LANGUAGE.TYPESCRIPT),
        ('.go', LANGUAGE.GO),
    ]
)
def test_is_in_multiline_comment_cstyle_outside(suffix, language):
    """Test detection of match outside C-style multi-line comment."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("const x = 1;\n")
        f.write("/* This is a comment */\n")
        f.write("const pattern = value;\n")
        f.flush()

        # Byte offset at "pattern" which is after the comment
        byte_offset = len("const x = 1;\n/* This is a comment */\nconst ".encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, language, byte_offset=byte_offset) is False
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,language",
    [
        ('.js', LANGUAGE.JAVASCRIPT),
        ('.ts', LANGUAGE.TYPESCRIPT),
        ('.go', LANGUAGE.GO),
    ]
)
def test_is_in_multiline_comment_cstyle_nested(suffix, language):
    """Test detection with multiple C-style comment blocks."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("/* comment 1 */\n")
        f.write("const x = 1;\n")
        f.write("/* comment 2\n")
        f.write("pattern\n")
        f.write("*/\n")
        f.flush()

        # Byte offset at "pattern" in the second comment block
        byte_offset = len("/* comment 1 */\nconst x = 1;\n/* comment 2\n".encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, language, byte_offset=byte_offset) is True
        finally:
            os.unlink(f.name)


def test_is_in_multiline_comment_python_inside():
    """Test detection of match inside Python docstring."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('def foo():\n')
        f.write('    """\n')
        f.write('    This function uses os.homedir()\n')
        f.write('    """\n')
        f.write('    pass\n')
        f.flush()

        # Byte offset at "os.homedir()" inside the docstring
        byte_offset = len('def foo():\n    """\n    This function uses '.encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, LANGUAGE.PYTHON, byte_offset=byte_offset) is True
        finally:
            os.unlink(f.name)


def test_is_in_multiline_comment_python_outside():
    """Test detection of match outside Python docstring."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('def foo():\n')
        f.write('    """\n')
        f.write('    This is a docstring\n')
        f.write('    """\n')
        f.write('    return os.homedir()\n')
        f.flush()

        # Byte offset at "os.homedir()" which is after the docstring
        byte_offset = len('def foo():\n    """\n    This is a docstring\n    """\n    return '.encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, LANGUAGE.PYTHON, byte_offset=byte_offset) is False
        finally:
            os.unlink(f.name)


def test_is_in_multiline_comment_python_triple_single_quotes():
    """Test detection with Python triple single quotes."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("def foo():\n")
        f.write("    '''\n")
        f.write("    Uses os.userInfo()\n")
        f.write("    '''\n")
        f.write("    pass\n")
        f.flush()

        # Byte offset at "os.userInfo()" inside the docstring
        byte_offset = len("def foo():\n    '''\n    Uses ".encode())

        try:
            assert Analyzer._is_in_multiline_comment(f.name, LANGUAGE.PYTHON, byte_offset=byte_offset) is True
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,comment_marker,code_line",
    [
        ('.py', '#', "import os"),
        ('.rb', '#', "require 'etc'"),
    ]
)
def test_is_match_in_comment_hash_single_line(suffix, comment_marker, code_line):
    """Test single-line hash comment detection for Python and Ruby."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write(f"{comment_marker} This is a comment\n")
        f.write(f"{code_line}\n")
        f.flush()

        try:
            # Line 1 is a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=1) is True
            # Line 2 is not a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=2) is False
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,code_line",
    [
        ('.js', "const os = require('os');"),
        ('.ts', "import * as os from 'os';"),
        ('.go', "import \"os\""),
    ]
)
def test_is_match_in_comment_slash_single_line(suffix, code_line):
    """Test single-line slash comment detection for JS/TS/Go."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("// This is a comment\n")
        f.write(f"{code_line}\n")
        f.flush()

        try:
            # Line 1 is a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=1) is True
            # Line 2 is not a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=2) is False
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,code_line",
    [
        ('.py', "home = os.homedir()"),
        ('.js', "const userInfo = os.userInfo();"),
        ('.ts', "const userInfo = os.userInfo();"),
        ('.go', "user := os.Getenv(\"USER\")"),
        ('.rb', "user = Etc.getlogin"),
    ]
)
def test_is_match_in_comment_code_not_comment(suffix, code_line):
    """Test that regular code is not detected as comment."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("// Some comment or import\n")
        f.write(f"{code_line}\n")
        f.flush()

        try:
            # Line 2 is code, not a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=2) is False
        finally:
            os.unlink(f.name)


@pytest.mark.parametrize(
    "suffix,code_line",
    [
        ('.js', "function foo() {}"),
        ('.ts', "declare function userInfo(): UserInfo;"),
        ('.go', "func main() {}"),
    ]
)
def test_is_match_in_comment_block_multiline(suffix, code_line):
    """Test C-style /* */ multi-line comment detection for JS/TS/Go."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write("/**\n")
        f.write(" * Block comment with pattern\n")
        f.write(" * More comment content\n")
        f.write(" */\n")
        f.write(f"{code_line}\n")
        f.flush()

        try:
            # Lines 2 and 3 are inside the block comment
            assert Analyzer.is_match_in_comment(f.name, line_number=2) is True
            assert Analyzer.is_match_in_comment(f.name, line_number=3) is True
            # Line 5 is not a comment
            assert Analyzer.is_match_in_comment(f.name, line_number=5) is False
        finally:
            os.unlink(f.name)


def test_is_match_in_comment_with_byte_offset():
    """Test that byte_offset optimization works correctly."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write("const x = 1;\n")
        f.write("/* comment\n")
        f.write("with os.userInfo()\n")
        f.write("*/\n")
        f.write("const y = 2;\n")
        f.flush()

        # Calculate byte offset for line 3
        byte_offset = len("const x = 1;\n/* comment\n".encode())

        try:
            # Line 3 is inside comment, passing byte_offset for optimization
            assert Analyzer.is_match_in_comment(f.name, line_number=3, byte_offset=byte_offset) is True
        finally:
            os.unlink(f.name)
