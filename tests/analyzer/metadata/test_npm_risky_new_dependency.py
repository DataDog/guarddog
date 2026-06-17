import json
from types import SimpleNamespace

import pytest

from guarddog.analyzer.metadata.npm import risky_new_dependency
from guarddog.analyzer.metadata.npm.risky_new_dependency import (
    DependencyRisk,
    NPMRiskyNewDependencyDetector,
)


def make_info(versions_deps, times, latest, name="parent"):
    """Build a minimal npm registry metadata dict."""
    return {
        "name": name,
        "dist-tags": {"latest": latest},
        "versions": {v: {"dependencies": deps} for v, deps in versions_deps.items()},
        "time": times,
    }


# 1.0.0 published before 1.1.0; 1.1.0 adds dependency "b".
ADDED_DEP_INFO = make_info(
    versions_deps={
        "1.0.0": {"a": "^1.0.0"},
        "1.1.0": {"a": "^1.0.0", "b": "^2.0.0"},
    },
    times={
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.1.0": "2020-06-01T00:00:00.000Z",
        "modified": "2020-06-01T00:00:00.000Z",
    },
    latest="1.1.0",
)


class TestDetectLogic:
    detector = NPMRiskyNewDependencyDetector()

    def _patch_scan(self, monkeypatch, mapping):
        """Replace the subprocess sub-scan with a deterministic mapping."""
        monkeypatch.setattr(
            self.detector,
            "_scan_dependency",
            lambda dep_name, spec: mapping.get(dep_name),
        )

    def test_risky_new_dependency_flagged(self, monkeypatch):
        self._patch_scan(
            monkeypatch,
            {
                "b": DependencyRisk(
                    "2.0.0", 7.5, "high_risk", ["npm-exfiltrate-sensitive-data"]
                )
            },
        )
        matched, message = self.detector.detect(ADDED_DEP_INFO, version="1.1.0")
        assert matched is True
        assert message is not None
        assert "b@2.0.0" in message
        # label-based phrasing (mirrors GuardDog's assessment wording), not "malicious"
        assert risky_new_dependency._LABEL_PHRASE["high_risk"] in message
        assert "malicious" not in message
        assert "npm-exfiltrate-sensitive-data" in message  # which rule matched
        assert "1.0.0" in message  # references the previous version

    def test_low_scoring_new_dependency_not_flagged(self, monkeypatch):
        self._patch_scan(monkeypatch, {"b": DependencyRisk("2.0.0", 3.0, "low")})
        matched, message = self.detector.detect(ADDED_DEP_INFO, version="1.1.0")
        assert matched is False
        assert message == ""

    def test_version_bump_of_existing_dependency_not_flagged(self, monkeypatch):
        info = make_info(
            versions_deps={
                "1.0.0": {"a": "^1.0.0"},
                "1.1.0": {"a": "^2.0.0"},
            },
            times={
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
            },
            latest="1.1.0",
        )

        def fail(*args, **kwargs):
            raise AssertionError("should not scan when no dependency was added")

        monkeypatch.setattr(self.detector, "_scan_dependency", fail)
        matched, _ = self.detector.detect(info, version="1.1.0")
        assert matched is False

    def test_earliest_version_has_no_previous(self, monkeypatch):
        def fail(*args, **kwargs):
            raise AssertionError("should not scan when there is no previous version")

        monkeypatch.setattr(self.detector, "_scan_dependency", fail)
        matched, _ = self.detector.detect(ADDED_DEP_INFO, version="1.0.0")
        assert matched is False

    def test_latest_resolved_when_version_omitted(self, monkeypatch):
        self._patch_scan(monkeypatch, {"b": DependencyRisk("2.0.0", 8.0, "high_risk")})
        matched, message = self.detector.detect(ADDED_DEP_INFO)
        assert matched is True
        assert message is not None
        assert "b@2.0.0" in message

    def test_only_risky_dep_appears_in_message(self, monkeypatch):
        info = make_info(
            versions_deps={
                "1.0.0": {"a": "^1.0.0"},
                "1.1.0": {"a": "^1.0.0", "good": "^1.0.0", "bad": "^2.0.0"},
            },
            times={
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
            },
            latest="1.1.0",
        )
        self._patch_scan(
            monkeypatch,
            {
                "good": DependencyRisk("1.0.0", 1.0, "low"),
                "bad": DependencyRisk("2.0.0", 9.0, "high_risk"),
            },
        )
        matched, message = self.detector.detect(info, version="1.1.0")
        assert matched is True
        assert message is not None
        assert "bad@2.0.0" in message
        assert "good" not in message


class TestScanDependencySubprocess:
    detector = NPMRiskyNewDependencyDetector()

    def _fake_run(self, captured, stdout):
        def run(command, **kwargs):
            captured.append(command)
            return SimpleNamespace(stdout=stdout, stderr="")

        return run

    def test_subscan_excludes_all_metadata_rules(self, monkeypatch):
        from guarddog.analyzer.metadata import get_metadata_detectors
        from guarddog.ecosystems import ECOSYSTEM

        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )
        captured: list = []
        stdout = json.dumps({"risk_score": {"score": 6.0, "label": "suspicious"}})
        monkeypatch.setattr(
            risky_new_dependency.subprocess, "run", self._fake_run(captured, stdout)
        )
        monkeypatch.delenv("GUARDDOG_SUBSCAN_SANDBOX", raising=False)

        result = self.detector._scan_dependency("b", "^2.0.0")
        assert result == DependencyRisk("2.0.0", 6.0, "suspicious", [])

        command = captured[0]
        excluded = {
            command[i + 1] for i, tok in enumerate(command) if tok == "--exclude-rules"
        }
        metadata_rules = set(get_metadata_detectors(ECOSYSTEM.NPM).keys())
        # source-code only: every metadata rule excluded, including this one (no recursion)
        assert excluded == metadata_rules
        assert "risky_new_dependency" in excluded
        assert command[command.index("--version") + 1] == "2.0.0"
        assert "--sandbox" not in command and "--no-sandbox" not in command

    @pytest.mark.parametrize(
        "env_value,expected_flag",
        [("1", "--sandbox"), ("0", "--no-sandbox")],
    )
    def test_sandbox_flag_propagated(self, monkeypatch, env_value, expected_flag):
        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )
        captured: list = []
        stdout = json.dumps({"risk_score": {"score": 6.0, "label": "suspicious"}})
        monkeypatch.setattr(
            risky_new_dependency.subprocess, "run", self._fake_run(captured, stdout)
        )
        monkeypatch.setenv("GUARDDOG_SUBSCAN_SANDBOX", env_value)

        self.detector._scan_dependency("b", "^2.0.0")
        assert expected_flag in captured[0]

    def test_unparseable_output_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: None
        )
        monkeypatch.setattr(
            risky_new_dependency.subprocess,
            "run",
            lambda command, **kwargs: SimpleNamespace(stdout="not json", stderr="boom"),
        )
        assert self.detector._scan_dependency("b", "^2.0.0") is None

    def test_timeout_returns_none(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )

        def raise_timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 1)

        monkeypatch.setattr(risky_new_dependency.subprocess, "run", raise_timeout)
        assert self.detector._scan_dependency("b", "^2.0.0") is None

    def test_missing_risk_score_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )
        stdout = json.dumps({"issues": 0, "errors": {"download-package": "404"}})
        monkeypatch.setattr(
            risky_new_dependency.subprocess,
            "run",
            lambda command, **kwargs: SimpleNamespace(stdout=stdout, stderr=""),
        )
        assert self.detector._scan_dependency("b", "^2.0.0") is None

    def test_matched_rules_collected_from_risks(self, monkeypatch):
        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )
        stdout = json.dumps(
            {
                "risk_score": {"score": 8.0, "label": "high_risk"},
                "risks": [
                    {"threat_rule": "npm-exec-base64"},
                    {"threat_rule": "npm-exfiltrate-sensitive-data"},
                    {"threat_rule": "npm-exec-base64"},  # duplicate, deduped
                ],
            }
        )
        monkeypatch.setattr(
            risky_new_dependency.subprocess,
            "run",
            lambda command, **kwargs: SimpleNamespace(stdout=stdout, stderr=""),
        )
        result = self.detector._scan_dependency("b", "^2.0.0")
        assert result is not None
        assert result.matched_rules == [
            "npm-exec-base64",
            "npm-exfiltrate-sensitive-data",
        ]

    def test_matched_rules_fall_back_to_metadata_results(self, monkeypatch):
        monkeypatch.setattr(
            risky_new_dependency, "highest_matching_version", lambda n, s: "2.0.0"
        )
        stdout = json.dumps(
            {
                "risk_score": {"score": 6.0, "label": "suspicious"},
                "risks": [],
                "results": {"typosquatting": "looks like express", "shady": None},
            }
        )
        monkeypatch.setattr(
            risky_new_dependency.subprocess,
            "run",
            lambda command, **kwargs: SimpleNamespace(stdout=stdout, stderr=""),
        )
        result = self.detector._scan_dependency("b", "^2.0.0")
        assert result is not None
        assert result.matched_rules == ["typosquatting"]
