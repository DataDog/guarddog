import re

from guarddog.reporters.human_readable import HumanReadableReporter, _sanitize

# Strips ANSI SGR/CSI/OSC sequences emitted by termcolor so assertions can match
# the underlying text instead of color codes.
_ANSI_SEQ_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_color(text: str) -> str:
    return _ANSI_SEQ_RE.sub("", text)


def _has_raw_escape(text: str, *, allow_color: bool = True) -> bool:
    """True if `text` still contains a raw ESC byte after optionally removing
    termcolor's own SGR sequences. The reporter is allowed to emit color codes
    via termcolor; what we need to prove is that *attacker-controlled* escape
    bytes don't survive."""
    candidate = _strip_color(text) if allow_color else text
    return "\x1b" in candidate or "\x07" in candidate


def test_sanitize_escapes_control_bytes_to_visible_literals():
    assert _sanitize("evil\x1b[2J.py") == "evil\\x1b[2J.py"
    assert _sanitize("bell\x07end") == "bell\\x07end"
    assert _sanitize("cr\x0dlf") == "cr\\x0dlf"


def test_sanitize_preserves_newlines_tabs_and_unicode():
    assert _sanitize("a\nb\tc") == "a\nb\tc"
    assert _sanitize("café — déjà vu") == "café — déjà vu"


def test_sanitize_neutralizes_osc_8_hyperlink():
    payload = "\x1b]8;;https://attacker.example\x07click\x1b]8;;\x07"
    sanitized = _sanitize(payload)
    assert "\x1b" not in sanitized
    assert "\x07" not in sanitized
    assert "https://attacker.example" in sanitized


def test_print_scan_results_escapes_malicious_filename_in_location():
    results = {
        "issues": 1,
        "errors": {},
        "results": {
            "some-rule": [
                {
                    "location": "evil\x1b[2J.py:3",
                    "code": "x = 1",
                    "message": "match",
                }
            ]
        },
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert not _has_raw_escape(out)
    assert "evil\\x1b[2J.py:3" in _strip_color(out)


def test_print_scan_results_escapes_osc_hyperlink_in_message():
    results = {
        "issues": 1,
        "errors": {},
        "results": {
            "some-rule": [
                {
                    "location": "ok.py:1",
                    "code": "x = 1",
                    "message": "\x1b]8;;https://attacker.example\x07evil\x1b]8;;\x07",
                }
            ]
        },
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert not _has_raw_escape(out)
    assert "https://attacker.example" in _strip_color(out)


def test_print_scan_results_escapes_code_snippet_but_keeps_newlines_tabs():
    results = {
        "issues": 1,
        "errors": {},
        "results": {
            "some-rule": [
                {
                    "location": "ok.py:1",
                    "code": "line1\nline2\twith\x07bell\x0dcr",
                    "message": "match",
                }
            ]
        },
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    plain = _strip_color(out)
    assert not _has_raw_escape(out)
    assert "\\x07" in plain
    assert "\\x0d" in plain
    # The code formatter expands \n into "\n    " for indentation; the line
    # boundary must survive sanitization.
    assert "line1\n" in plain
    # \t in the snippet is replaced with two spaces by the formatter.
    assert "line2  with" in plain


def test_print_scan_results_escapes_malicious_identifier():
    results = {"issues": 0, "errors": {}, "results": {}}
    out = HumanReadableReporter.print_scan_results("pkg\x1b[31mred", results)
    assert not _has_raw_escape(out)
    assert "pkg\\x1b[31mred" in _strip_color(out)


def test_print_scan_results_escapes_metadata_description():
    results = {
        "issues": 1,
        "errors": {},
        "results": {
            "metadata-rule": "found suspicious file evil\x1b[2J.py",
        },
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert not _has_raw_escape(out)
    assert "evil\\x1b[2J.py" in _strip_color(out)


def test_print_errors_escapes_attacker_controlled_error_message():
    results = {
        "errors": {
            "rule-x": "failed to run rule rule-x: open evil\x1b[2J.py: no such file",
        },
    }
    out = HumanReadableReporter.print_errors("pkg\x1b[31m", results)
    assert not _has_raw_escape(out)
    plain = _strip_color(out)
    assert "evil\\x1b[2J.py" in plain
    assert "pkg\\x1b[31m" in plain


def test_print_scan_results_benign_input_is_preserved():
    results = {
        "issues": 1,
        "errors": {},
        "results": {
            "rule-name": [
                {
                    "location": "café/módulo.py:42",
                    "code": "print('déjà vu')",
                    "message": "matched a benign-looking pattern",
                }
            ]
        },
    }
    out = HumanReadableReporter.print_scan_results("requests", results)
    plain = _strip_color(out)
    assert "café/módulo.py:42" in plain
    assert "print('déjà vu')" in plain
    assert "matched a benign-looking pattern" in plain
    assert "requests" in plain
    assert "rule-name" in plain
