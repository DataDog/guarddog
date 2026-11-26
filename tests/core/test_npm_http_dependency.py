"""
Analyzer-level regression tests for threat-npm-http-dependency.

The direct YARA tests in tests/analyzer/sourcecode only compile and match the
.yar file. These tests go through Analyzer.analyze_sourcecode, which is what the
CLI uses, so they also cover how findings (location, match, message) are built.

Signal definition used here: a URL dependency signal means an HTTP/HTTPS URL used
as the specifier of an entry in one of the top-level dependency maps
(dependencies, devDependencies, optionalDependencies, peerDependencies). It is a
review signal, not a malware label. Every URL uses the reserved .invalid TLD or
documentation IP ranges; nothing is installed, executed or fetched.
"""

import json
import os
import sys
import tempfile

import pytest

from guarddog import ecosystems
from guarddog.analyzer.analyzer import Analyzer
from guarddog.analyzer.sourcecode import npm_http_dependency

RULE = "threat-npm-http-dependency"
npm_analyzer = Analyzer(ecosystem=ecosystems.ECOSYSTEM.NPM)
RESOURCES = os.path.join(os.path.dirname(__file__), "resources")


def _scan(files: dict, rules=frozenset({RULE})) -> dict:
    with tempfile.TemporaryDirectory() as package_dir:
        for relpath, content in files.items():
            full_path = os.path.join(package_dir, relpath)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        return npm_analyzer.analyze_sourcecode(package_dir, set(rules))


def _manifest(**fields) -> str:
    return json.dumps({"name": "fixture", "version": "1.0.0", **fields}, indent=2)


def _findings(result: dict) -> list:
    return result["results"].get(RULE) or []


# URLs outside the top-level dependency maps are not dependency specifiers.
NOT_A_DEPENDENCY_URL = {
    "contributors_array": _manifest(
        contributors=[
            {"name": "A", "url": "http://a.example.invalid"},
            {"name": "B", "url": "http://b.example.invalid"},
        ]
    ),
    "funding_array": _manifest(
        funding=[
            {"type": "individual", "url": "http://one.example.invalid"},
            {"type": "patreon", "url": "http://two.example.invalid"},
        ]
    ),
    "jest_test_url": _manifest(jest={"testURL": "http://localhost"}),
    "config_endpoint": _manifest(config={"endpoint": "http://service.example.invalid"}),
    "nested_config_dependencies": _manifest(
        customConfig={"dependencies": {"fixture": "http://example.invalid/a"}}
    ),
    "homepage_ip": _manifest(homepage="http://192.0.2.1"),
    "homepage_http_archive": _manifest(homepage="http://example.invalid/docs.tgz"),
    "homepage_https_archive": _manifest(homepage="https://example.invalid/docs.tgz"),
    "repository_archive": _manifest(
        repository={"type": "git", "url": "https://example.invalid/repo.tgz"}
    ),
    "license_url": _manifest(
        license={"type": "MIT", "url": "http://example.invalid/license"}
    ),
    # Git and local specifiers are covered by other rules, not this one.
    "git_https_dependency": _manifest(
        dependencies={"example-lib": "git+https://example.invalid/repo.git"}
    ),
    "local_file_dependency": _manifest(dependencies={"example-lib": "file:../fixture"}),
    "registry_range": _manifest(dependencies={"example-lib": "^1.0.0"}),
}


def test_metadata_urls_fixture_is_not_reported():
    """
    Formerly the direct YARA benign fixture. The YARA rule now only selects
    candidate manifests, so this manifest is a YARA candidate and the "not a
    dependency" decision is checked at the Analyzer level instead.
    """
    with open(os.path.join(RESOURCES, "npm-http-dependency-metadata-urls.json")) as f:
        result = _scan({"package.json": f.read()})
    assert RULE not in result["errors"]
    assert _findings(result) == []


@pytest.mark.parametrize("case", sorted(NOT_A_DEPENDENCY_URL))
def test_url_outside_dependency_maps_is_not_reported(case):
    result = _scan({"package.json": NOT_A_DEPENDENCY_URL[case]})
    assert RULE not in result["errors"]
    assert _findings(result) == []


def _large_map() -> str:
    deps = {f"pkg-{i:03d}": "^1.0.0" for i in range(60)}
    deps["late-dep"] = "http://example.invalid/pkg"
    return _manifest(dependencies=deps)


# (manifest, field, dependency name, url) for the dependency that must be reported.
DEPENDENCY_URL = {
    "dependencies_http": (
        _manifest(dependencies={"example-lib": "http://example.invalid/pkg"}),
        "dependencies",
        "example-lib",
        "http://example.invalid/pkg",
    ),
    "dev_http": (
        _manifest(devDependencies={"example-lib": "http://example.invalid/pkg"}),
        "devDependencies",
        "example-lib",
        "http://example.invalid/pkg",
    ),
    "optional_http": (
        _manifest(optionalDependencies={"example-lib": "http://example.invalid/pkg"}),
        "optionalDependencies",
        "example-lib",
        "http://example.invalid/pkg",
    ),
    "peer_http": (
        _manifest(peerDependencies={"example-lib": "http://example.invalid/pkg"}),
        "peerDependencies",
        "example-lib",
        "http://example.invalid/pkg",
    ),
    "https_archive": (
        _manifest(dependencies={"example-lib": "https://example.invalid/pkg.tgz"}),
        "dependencies",
        "example-lib",
        "https://example.invalid/pkg.tgz",
    ),
    "https_ip": (
        _manifest(dependencies={"example-lib": "https://192.0.2.10/pkg"}),
        "dependencies",
        "example-lib",
        "https://192.0.2.10/pkg",
    ),
    # Dependency names that collide with metadata keys are still dependencies.
    "named_url": (
        _manifest(dependencies={"url": "http://example.invalid/pkg"}),
        "dependencies",
        "url",
        "http://example.invalid/pkg",
    ),
    "named_homepage": (
        _manifest(dependencies={"homepage": "http://example.invalid/pkg"}),
        "dependencies",
        "homepage",
        "http://example.invalid/pkg",
    ),
    "named_author": (
        _manifest(dependencies={"author": "http://example.invalid/pkg"}),
        "dependencies",
        "author",
        "http://example.invalid/pkg",
    ),
    "named_url_after_funding_strings": (
        _manifest(
            funding=["https://example.invalid/sponsor"],
            dependencies={"url": "http://example.invalid/pkg"},
        ),
        "dependencies",
        "url",
        "http://example.invalid/pkg",
    ),
    "minified_named_homepage": (
        '{"name":"fixture","dependencies":{"homepage":"http://example.invalid/pkg"},'
        '"homepage":"http://example.invalid"}',
        "dependencies",
        "homepage",
        "http://example.invalid/pkg",
    ),
    "large_dependency_map": (
        _large_map(),
        "dependencies",
        "late-dep",
        "http://example.invalid/pkg",
    ),
}


@pytest.mark.parametrize("case", sorted(DEPENDENCY_URL))
def test_dependency_url_is_reported(case):
    manifest = DEPENDENCY_URL[case][0]
    result = _scan({"package.json": manifest})
    assert RULE not in result["errors"]
    assert _findings(result), f"{case}: expected a URL dependency signal"


@pytest.mark.parametrize("case", sorted(DEPENDENCY_URL))
def test_finding_names_field_dependency_and_url(case):
    """The message must say which field, which dependency and which full URL."""
    manifest, field, name, url = DEPENDENCY_URL[case]
    findings = _findings(_scan({"package.json": manifest}))
    assert any(url in finding["match"] for finding in findings)
    assert any(
        field in finding["message"]
        and name in finding["message"]
        and url in finding["message"]
        for finding in findings
    ), [finding["message"] for finding in findings]


METADATA_URLS = (
    "http://example.invalid/home",
    "http://example.invalid/author",
    "http://example.invalid/bugs",
    "http://example.invalid/repo.git",
)
MIXED = _manifest(
    homepage=METADATA_URLS[0],
    author={"name": "A", "url": METADATA_URLS[1]},
    bugs={"url": METADATA_URLS[2]},
    repository={"type": "git", "url": METADATA_URLS[3]},
    dependencies={"first": "^1.0.0", "example-lib": "http://example.invalid/pkg"},
)


def test_evidence_is_the_dependency_not_metadata():
    """
    Metadata URLs must not be listed as dependency evidence. With max_hits=3 they
    can otherwise use up every slot and hide the real dependency entirely.
    """
    findings = _findings(_scan({"package.json": MIXED}))
    assert findings
    for finding in findings:
        for metadata_url in METADATA_URLS:
            assert metadata_url not in finding["match"]
            assert metadata_url not in finding["code"]
    assert any("http://example.invalid/pkg" in f["match"] for f in findings)


def test_location_points_at_the_dependency_line():
    lines = MIXED.splitlines()
    expected_line = next(
        number for number, line in enumerate(lines, start=1) if '"example-lib"' in line
    )
    findings = _findings(_scan({"package.json": MIXED}))
    assert [f["location"] for f in findings] == [f"package.json:{expected_line}"]


def test_max_hits_is_preserved():
    deps = {f"dep-{i}": f"http://example.invalid/{i}" for i in range(5)}
    findings = _findings(_scan({"package.json": _manifest(dependencies=deps)}))
    assert 1 <= len(findings) <= 3


def test_path_include_is_preserved():
    dependency = _manifest(dependencies={"example-lib": "http://example.invalid/pkg"})
    assert _findings(_scan({"sub/package.json": dependency}))
    assert not _findings(_scan({"docs/example.json": dependency}))


def test_rule_selection_is_preserved():
    dependency = _manifest(dependencies={"example-lib": "http://example.invalid/pkg"})
    result = _scan({"package.json": dependency}, rules={"threat-npm-preinstall-script"})
    assert RULE not in result["results"]


# Candidate manifests (they contain a quoted http(s) URL) whose dependency
# structure cannot be read unambiguously are reported as a rule error, never as
# a clean result. They are excluded from accuracy denominators.
UNCLEAR_INPUT = {
    "invalid_json": '{"dependencies":{"example-lib":"http://example.invalid/pkg",}',
    "duplicate_field": '{"dependencies":{"one":"http://example.invalid/pkg"},'
    '"dependencies":{"one":"^1.0.0"}}',
    "duplicate_dependency": '{"dependencies":{"one":"http://example.invalid/pkg",'
    '"one":"^1.0.0"}}',
    "dependency_map_wrong_type": '{"dependencies":"http://example.invalid/pkg"}',
    "dependency_value_wrong_type": '{"homepage":"http://example.invalid",'
    '"dependencies":{"example-lib":123}}',
    "not_an_object": '["http://example.invalid/pkg"]',
}


@pytest.mark.parametrize("case", sorted(UNCLEAR_INPUT))
def test_unclear_manifest_is_reported_as_rule_error(case):
    result = _scan({"package.json": UNCLEAR_INPUT[case]})
    assert "package.json" in result["errors"].get(RULE, "")


def test_duplicate_dependency_field_without_other_findings():
    result = _scan({"package.json": UNCLEAR_INPUT["duplicate_field"]})
    assert "dependencies is defined more than once" in result["errors"][RULE]
    assert _findings(result) == []


def test_duplicate_dependency_field_preserves_other_fields():
    manifest = (
        '{"dependencies":{"one":"http://example.invalid/first"},'
        '"dependencies":{"two":"http://example.invalid/second"},'
        '"devDependencies":{"three":"http://example.invalid/third"}}'
    )
    result = _scan({"package.json": manifest})
    assert "dependencies is defined more than once" in result["errors"][RULE]
    assert [f["match"] for f in _findings(result)] == ["http://example.invalid/third"]


def test_duplicate_dependency_name_preserves_other_entries_in_same_field():
    manifest = (
        '{"dependencies":{"one":"http://example.invalid/first",'
        '"one":"http://example.invalid/second","two":"http://example.invalid/third"}}'
    )
    result = _scan({"package.json": manifest})
    assert 'dependencies["one"] is defined more than once' in result["errors"][RULE]
    assert [f["match"] for f in _findings(result)] == ["http://example.invalid/third"]


def test_problem_does_not_hide_urls_in_well_formed_maps():
    manifest = (
        '{"devDependencies":"oops",'
        '"dependencies":{"example-lib":"http://example.invalid/pkg"}}'
    )
    result = _scan({"package.json": manifest})
    assert "devDependencies is not an object" in result["errors"][RULE]
    assert [f["match"] for f in _findings(result)] == ["http://example.invalid/pkg"]


def test_manifest_without_any_url_is_not_inspected():
    """
    Documented scope: without a quoted http(s) URL the YARA candidate filter does
    not select the file, so it cannot hold a URL dependency and its structure is
    not checked by this rule.
    """
    result = _scan({"package.json": '{"dependencies":{"example-lib":123}}'})
    assert RULE not in result["errors"]
    assert _findings(result) == []


def test_unreadable_manifest_does_not_stop_other_files():
    dependency = _manifest(dependencies={"example-lib": "http://example.invalid/pkg"})
    result = _scan(
        {
            "a/package.json": '{"dependencies":{"x":"http://example.invalid/a",}',
            "b/package.json": dependency,
        }
    )
    assert "a/package.json" in result["errors"][RULE]
    assert [f["location"].split(":")[0] for f in _findings(result)] == [
        "b/package.json"
    ]


# Escaped and query-string forms were not reported before; this change keeps
# them out (extending coverage is a separate policy decision).
UNCHANGED_EXTENSION_CASES = {
    "escaped_slashes": '{"dependencies":{"example-lib":"http:\\/\\/example.invalid/pkg"}}',
    "unicode_escape": '{"dependencies":{"example-lib":"http\\u003a//example.invalid/pkg"}}',
    "archive_with_query": _manifest(
        dependencies={"example-lib": "https://example.invalid/pkg.tgz?token=1"}
    ),
    "https_without_archive": _manifest(
        dependencies={"example-lib": "https://example.invalid/pkg"}
    ),
}


@pytest.mark.parametrize("case", sorted(UNCHANGED_EXTENSION_CASES))
def test_url_shapes_outside_existing_policy_stay_unreported(case):
    result = _scan({"package.json": UNCHANGED_EXTENSION_CASES[case]})
    assert RULE not in result["errors"]
    assert _findings(result) == []


# --- Cases found in review (2026-11-19) -------------------------------------


@pytest.mark.parametrize(
    "raw_url",
    [
        r"http://example.invalid/\u0061",
        r"http://example.invalid/a\/b",
        r"http://example\u002einvalid/a",
    ],
)
def test_escape_after_the_scheme_is_still_reported(raw_url):
    """The regex-only rule reported these; only an escaped scheme stays out."""
    result = _scan({"package.json": '{"dependencies":{"pkg":"' + raw_url + '"}}'})
    assert RULE not in result["errors"]
    findings = _findings(result)
    assert [f["match"] for f in findings] == [raw_url]
    assert raw_url in findings[0]["message"]


def test_same_url_elsewhere_does_not_make_escaped_dependency_reportable():
    manifest = (
        "{\n"
        '  "homepage": "http://example.invalid/pkg",\n'
        '  "dependencies": {"pkg": "http:\\/\\/example.invalid/pkg"}\n'
        "}"
    )
    result = _scan({"package.json": manifest})
    assert RULE not in result["errors"]
    assert _findings(result) == []


def test_location_is_the_dependency_even_with_escaped_name_and_same_url_in_config():
    manifest = (
        "{\n"
        '  "config": {"pkg": "http://example.invalid/pkg"},\n'
        '  "dependencies": {"p\\u006bg": "http://example.invalid/pkg"}\n'
        "}"
    )
    findings = _findings(_scan({"package.json": manifest}))
    assert [f["location"] for f in findings] == ["package.json:3"]
    assert 'dependencies["p\\u006bg"]' in findings[0]["message"]


def test_lone_surrogate_in_dependency_name_is_reported_not_an_error():
    manifest = '{"dependencies":{"\\ud800":"http://example.invalid/pkg"}}'
    result = _scan({"package.json": manifest})
    assert RULE not in result["errors"]
    assert [f["match"] for f in _findings(result)] == ["http://example.invalid/pkg"]


def _parser_limit_manifest(kind: str) -> str:
    if kind == "large_integer":
        limit = sys.get_int_max_str_digits()
        if limit == 0:
            pytest.skip("This interpreter disables the integer conversion limit.")
        value = "9" * max(5000, limit + 1)
    else:
        value = "[" * 10000 + "0" + "]" * 10000
    return (
        '{"custom":' + value + ',"dependencies":{"first":"http://example.invalid/a"}}'
    )


@pytest.mark.parametrize("kind", ["large_integer", "deep_nesting"])
def test_parser_limit_is_a_file_error_and_later_files_are_scanned(kind):
    dependency = _manifest(dependencies={"second": "http://example.invalid/b"})
    result = _scan(
        {"a/package.json": _parser_limit_manifest(kind), "b/package.json": dependency}
    )
    assert "a/package.json: could not be parsed" in result["errors"][RULE]
    assert [f["location"].split(":")[0] for f in _findings(result)] == [
        "b/package.json"
    ]


def test_evidence_is_built_only_for_kept_findings(monkeypatch):
    """Cost check without timing: snippets are built for at most max_hits URLs."""
    calls = []
    original = Analyzer.get_lines_around_offset

    def counting(self, *args, **kwargs):
        calls.append(args)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "get_lines_around_offset", counting)
    deps = {f"pkg-{i}": f"http://example.invalid/{i}" for i in range(2500)}
    findings = _findings(_scan({"package.json": json.dumps({"dependencies": deps})}))
    assert len(findings) == 3
    assert len(calls) == 3


# The walk must accept and reject exactly what json.loads does.
VALIDATION_INPUTS = [
    "{}",
    " {\n} ",
    '{"a":1,}',
    '{"a":1} x',
    '{"a" 1}',
    '{"a":1 "b":2}',
    "[1]",
    "[1] x",
    "",
    "   ",
    '{"dependencies":{"x":"http://e.invalid/a"},}',
    '{"dependencies":{"x":"http://e.invalid/a" "y":"1"}}',
    '{"dependencies":{"x":"a\tb"}}',
    '{"dependencies":{"x":"\\q"}}',
    '{"dependencies":{"x":[1,{"y":null}]}}',
    '{"dependencies":"x","devDependencies":{}}',
    '{"x":NaN}',
    '{"x":1e5,"y":-0.5,"z":true,"w":null}',
    '{"\\u00e9":"\\ud83d\\ude00"}',
]


@pytest.mark.parametrize("text", VALIDATION_INPUTS)
def test_walk_accepts_exactly_what_json_loads_accepts(text):
    try:
        json.loads(text)
        expected_valid = True
    except ValueError:
        expected_valid = False
    check = npm_http_dependency.check_manifest(text.encode("utf-8"))
    walk_valid = not any(p.startswith("not valid JSON") for p in check.problems)
    assert walk_valid == expected_valid, check.problems
