import re
from unittest import mock

from guarddog.reporters.human_readable import HumanReadableReporter, _sanitize

# Strips ANSI SGR/CSI/OSC sequences emitted by termcolor so assertions can match
# the underlying text instead of color codes.
_ANSI_SEQ_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_color(text: str) -> str:
    return _ANSI_SEQ_RE.sub("", text)


# OSC 8 hyperlink open (`\x1b]8;;URL\x1b\\`) and close (`\x1b]8;;\x1b\\`) wrappers.
_OSC8_RE = re.compile(r"\x1b\]8;;[^\x1b\x07]*(?:\x1b\\|\x07)")


def _visible_text(text: str) -> str:
    """Strip OSC 8 hyperlink wrappers and SGR colors, leaving what a user reads."""
    return _strip_color(_OSC8_RE.sub("", text))


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


def _risk(**overrides) -> dict:
    """A minimal formed-risk dict for exercising the findings render path."""
    risk = {
        "threat_rule": "some-rule",
        "threat_description": "match",
        "threat_location": "ok.py:1",
        "threat_code": "x = 1",
        "mitre_tactics": ["execution"],
        "severity": "low",
        "file_path": "ok.py",
    }
    risk.update(overrides)
    return risk


def test_print_scan_results_escapes_malicious_filename_in_location():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [
            _risk(threat_location="evil\x1b[2J.py:3", file_path="evil\x1b[2J.py")
        ],
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert not _has_raw_escape(out)
    assert "evil\\x1b[2J.py:3" in _strip_color(out)


def test_print_scan_results_escapes_osc_hyperlink_in_message():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [
            _risk(
                threat_description="\x1b]8;;https://attacker.example\x07evil\x1b]8;;\x07"
            )
        ],
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert not _has_raw_escape(out)
    assert "https://attacker.example" in _strip_color(out)


def test_print_scan_results_escapes_code_snippet_but_keeps_newlines_tabs():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [_risk(threat_code="line1\nline2\twith\x07bell\x0dcr")],
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    plain = _strip_color(out)
    assert not _has_raw_escape(out)
    assert "\\x07" in plain
    assert "\\x0d" in plain
    # The line boundary must survive sanitization.
    assert "line1\n" in plain
    # Tabs in the snippet are preserved (not expanded) on the findings path.
    assert "line2\twith" in plain


def test_print_scan_results_escapes_malicious_identifier():
    results = {"issues": 0, "errors": {}, "results": {}}
    out = HumanReadableReporter.print_scan_results("pkg\x1b[31mred", results)
    assert not _has_raw_escape(out)
    assert "pkg\\x1b[31mred" in _strip_color(out)


def test_print_scan_results_escapes_risk_description():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [
            _risk(
                threat_rule="metadata-rule",
                threat_description="found suspicious file evil\x1b[2J.py",
                threat_location="",
                threat_code="",
                file_path="",
            )
        ],
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
        "results": {},
        "risks": [
            _risk(
                threat_rule="rule-name",
                threat_description="matched a benign-looking pattern",
                threat_location="café/módulo.py:42",
                threat_code="print('déjà vu')",
                file_path="café/módulo.py",
            )
        ],
    }
    out = HumanReadableReporter.print_scan_results("requests", results)
    plain = _strip_color(out)
    assert "café/módulo.py:42" in plain
    assert "print('déjà vu')" in plain
    assert "matched a benign-looking pattern" in plain
    assert "requests" in plain
    assert "rule-name" in plain


def test_print_scan_results_shows_pypi_inspector_url_for_matching_remote_scan():
    project_url = "https://inspector.pypi.io/project/requests/2.28.1/"
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [_risk()],
        "pypi_inspector_url": project_url,
    }
    out = HumanReadableReporter.print_scan_results("requests", results)
    # The URL is the hyperlink target (present in the raw stream) but the visible
    # text is a short label, not the full URL.
    assert f"\x1b]8;;{project_url}\x1b\\" in out
    visible = _visible_text(out)
    assert "Package files: view on PyPI Inspector" in visible
    assert project_url not in visible


def test_print_scan_results_hides_pypi_inspector_url_without_matches():
    results = {
        "issues": 0,
        "errors": {},
        "results": {},
        "risks": [],
        "pypi_inspector_url": "https://inspector.pypi.io/project/requests/2.28.1/",
    }
    out = HumanReadableReporter.print_scan_results("requests", results)
    assert "inspector.pypi.io" not in _strip_color(out)


def test_print_scan_results_shows_per_finding_inspector_deep_link():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [
            _risk(
                threat_location="aws-dd-forwarder-1.0/lambda_function.py:31",
                file_path="aws-dd-forwarder-1.0/lambda_function.py",
            )
        ],
        "pypi_inspector_url": "https://inspector.pypi.io/project/aws-dd-forwarder/1.0/",
        "pypi_dist_path": "/packages/f8/57/87be/aws-dd-forwarder-1.0.tar.gz",
    }
    out = HumanReadableReporter.print_scan_results("aws-dd-forwarder", results)
    deep_url = (
        "https://inspector.pypi.io/project/aws-dd-forwarder/1.0/packages/f8/57/87be/"
        "aws-dd-forwarder-1.0.tar.gz/aws-dd-forwarder-1.0/lambda_function.py#line.31"
    )
    # The deep link is the finding location's hyperlink target; the visible text
    # stays the location, not the raw URL.
    assert f"\x1b]8;;{deep_url}\x1b\\" in out
    visible = _visible_text(out)
    assert "at aws-dd-forwarder-1.0/lambda_function.py:31" in visible
    assert deep_url not in visible
    # The project-level link is still shown alongside the deep links.
    assert "Package files:" in visible


def test_print_scan_results_no_deep_link_without_dist_path():
    results = {
        "issues": 1,
        "errors": {},
        "results": {},
        "risks": [_risk(threat_location="pkg/mod.py:3", file_path="pkg/mod.py")],
        "pypi_inspector_url": "https://inspector.pypi.io/project/pkg/1.0/",
    }
    out = HumanReadableReporter.print_scan_results("pkg", results)
    assert "#line." not in _strip_color(out)


def test_pypi_finding_inspector_url_encodes_path_and_requires_line():
    base = "https://inspector.pypi.io/project/pkg/1.0/packages/aa/bb/cc/pkg-1.0.tar.gz"
    url = HumanReadableReporter._pypi_finding_inspector_url(
        base, "pkg-1.0/sub dir/mod.py:12"
    )
    assert url == base + "/pkg-1.0/sub%20dir/mod.py#line.12"

    # Metadata findings have no line and get no deep link.
    assert HumanReadableReporter._pypi_finding_inspector_url(base, "") is None
    assert HumanReadableReporter._pypi_finding_inspector_url(base, "mod.py") is None


def test_hyperlink_wraps_label_in_osc8_sequence():
    link = HumanReadableReporter._hyperlink("https://example.com/x", "click me")
    assert link == "\x1b]8;;https://example.com/x\x1b\\click me\x1b]8;;\x1b\\"


def test_hyperlink_falls_back_to_plain_label_on_unsafe_url():
    # A URL carrying an ESC or BEL could terminate the escape sequence early, so
    # such urls are refused and only the bare label is returned.
    assert HumanReadableReporter._hyperlink("https://x/\x1b\\evil", "label") == "label"
    assert HumanReadableReporter._hyperlink("https://x/\x07evil", "label") == "label"


def test_strip_prefix():
    strip = HumanReadableReporter._strip_prefix
    # Strips a common ancestor; leaves non-descendants and edge cases untouched.
    assert (
        strip("package/dist/node/axios.cjs:42", "package/dist") == "node/axios.cjs:42"
    )
    assert strip("package/dist/axios.js:7", "package/dist/") == "axios.js:7"
    assert strip("other/file.js:1", "package/dist") == "other/file.js:1"
    assert strip("package/dist", "package/dist") == "package/dist"
    assert strip("axios.js:5", None) == "axios.js:5"

    # Under the scan sandbox os.getcwd() raises OSError; stripping must still
    # work via plain string ops rather than crashing through relpath/abspath.
    def blocked():
        raise PermissionError(1, "Operation not permitted")

    with mock.patch("os.getcwd", blocked):
        assert (
            strip("package/dist/node/axios.cjs:42", "package/dist")
            == "node/axios.cjs:42"
        )
