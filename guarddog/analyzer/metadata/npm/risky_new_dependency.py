"""Risky New Dependency Detector

When a new version of a package adds a dependency that was not present in the
previous published version, that dependency is scanned like any other package.
If it scores at or above the risk threshold, the parent package is flagged so a
maliciously introduced dependency surfaces on the parent scan.
"""

import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from guarddog.analyzer.metadata.detector import Detector
from guarddog.utils.config import NEW_DEPENDENCY_RISK_THRESHOLD
from guarddog.utils.npm import highest_matching_version, resolve_npm_alias

log = logging.getLogger("guarddog")


@dataclass
class DependencyRisk:
    """Outcome of scanning a single newly added dependency."""

    version: str
    score: float
    label: str
    matched_rules: List[str] = field(default_factory=list)


# Upper bound on a single sub-dependency scan so one slow scan can't hang the parent.
SUBSCAN_TIMEOUT_SECONDS = 300

# Keys in the registry `time` object that are not version publish timestamps.
_NON_VERSION_TIME_KEYS = {"created", "modified"}

# Risk labels phrased to match GuardDog's overall assessment wording.
_LABEL_PHRASE = {
    "high_risk": "high risk",
    "suspicious": "suspicious",
    "low": "low risk",
}


class NPMRiskyNewDependencyDetector(Detector):
    """Detects dependencies newly introduced in a version that are themselves risky.

    The previous published version is determined from the registry `time` map; any
    dependency name present in the scanned version but absent from the previous one
    is scanned as a standalone package. Each sub-scan runs as a subprocess invocation
    of guarddog, so it is sandboxed identically to the parent, and excludes this rule
    so the check never recurses beyond one level."""

    def __init__(self):
        super().__init__(
            name="risky_new_dependency",
            description="Identify newly added dependencies that are themselves risky. "
            "A dependency introduced in this version but absent from the previous one "
            "is scanned as a package; it is flagged when its risk score is high.",
            identifies="threat.npm.risky-new-dependency",
            severity="high",
            mitre_tactics="initial-access",
            specificity="high",
            sophistication="low",
        )

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        package_name = name or package_info.get("name", "")
        versions = package_info.get("versions", {})
        current_version = version or package_info.get("dist-tags", {}).get("latest")
        if not current_version or current_version not in versions:
            log.debug(
                f"[{self.name}] No usable version for '{package_name}' "
                f"(resolved '{current_version}'); skipping"
            )
            return False, None

        previous_version = self._previous_published_version(
            package_info, current_version
        )
        if previous_version is None:
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' has no previous "
                f"published version; skipping"
            )
            return False, None

        current_deps = self._installed_dependencies(versions.get(current_version, {}))
        previous_deps = self._installed_dependencies(versions.get(previous_version, {}))
        new_dependencies = set(current_deps) - set(previous_deps)
        if not new_dependencies:
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' adds no new "
                f"dependencies vs '{previous_version}'; skipping"
            )
            return False, None

        log.debug(
            f"[{self.name}] '{package_name}@{current_version}' adds "
            f"{len(new_dependencies)} new dependency(ies) vs '{previous_version}': "
            f"{', '.join(sorted(new_dependencies))}"
        )

        findings = []
        for dep_name in sorted(new_dependencies):
            risk = self._scan_dependency(dep_name, current_deps[dep_name])
            if risk is None:
                log.debug(f"[{self.name}] Could not score new dependency '{dep_name}'")
                continue
            flagged = risk.score >= NEW_DEPENDENCY_RISK_THRESHOLD
            log.debug(
                f"[{self.name}] New dependency '{dep_name}@{risk.version}' scored "
                f"{risk.score} ({risk.label}); threshold {NEW_DEPENDENCY_RISK_THRESHOLD} "
                f"-> {'FLAGGED' if flagged else 'below threshold'}; "
                f"matched rules: {', '.join(risk.matched_rules) or 'none'}"
            )
            if flagged:
                matched = (
                    f" Matched rules: {', '.join(risk.matched_rules)}."
                    if risk.matched_rules
                    else ""
                )
                phrase = _LABEL_PHRASE.get(risk.label, risk.label or "risky")
                findings.append(
                    f"Newly added dependency {dep_name}@{risk.version} is {phrase} "
                    f"(risk score {risk.score}/10).{matched} It was introduced in "
                    f"{package_name}@{current_version} and was not a dependency of "
                    f"the previous version {previous_version}."
                )

        log.debug(
            f"[{self.name}] '{package_name}@{current_version}': "
            f"{len(findings)} risky new dependency(ies) found"
        )
        return len(findings) != 0, "\n".join(findings)

    def _previous_published_version(
        self, package_info, current_version: str
    ) -> Optional[str]:
        """Return the version published immediately before `current_version`.

        Publish times come from the registry `time` map; ISO 8601 timestamps sort
        lexicographically, so the previous version is the one with the greatest
        timestamp strictly before the current version's.
        """
        published = {
            v: t
            for v, t in package_info.get("time", {}).items()
            if v not in _NON_VERSION_TIME_KEYS and v in package_info.get("versions", {})
        }
        current_time = published.get(current_version)
        if current_time is None:
            return None

        earlier = [(t, v) for v, t in published.items() if t < current_time]
        if not earlier:
            return None
        return max(earlier)[1]

    @staticmethod
    def _installed_dependencies(version_info: dict) -> dict:
        """Map real package name -> version selector for the dependencies npm
        installs by default: `dependencies` and `optionalDependencies` (optional
        installs are non-fatal but still run). npm aliases are resolved to the real
        package so the diff and sub-scan target the aliased package, not the local
        alias name (e.g. "x": "npm:evil@1" -> {"evil": "1"})."""
        resolved: dict = {}
        for section in ("dependencies", "optionalDependencies"):
            for name, spec in (version_info.get(section) or {}).items():
                real_name, selector = resolve_npm_alias(name, spec)
                resolved[real_name] = selector
        return resolved

    def _scan_dependency(self, dep_name: str, spec: str) -> Optional[DependencyRisk]:
        """Scan a single dependency as a subprocess and return its risk outcome.

        The sub-scan runs with source-code rules only: every metadata rule is
        excluded. A maliciously introduced dependency reveals itself through its
        code (obfuscation, exec, exfiltration, install hooks), whereas metadata
        rules (typosquatting, manifest mismatch, ...) are a weak, noisy signal in
        this context. Excluding all metadata rules also excludes this one, so the
        check never recurses. Returns None when the scan can't be run or produced
        no score. The subprocess takes the same CLI path as a top-level scan, so
        it is sandboxed identically to the parent."""
        resolved_version = None
        try:
            resolved_version = highest_matching_version(dep_name, spec)
        except Exception as e:
            log.debug(f"Could not resolve version for {dep_name} ({spec}): {e}")
        log.debug(
            f"[{self.name}] Resolved '{dep_name}' spec '{spec}' to version "
            f"'{resolved_version or 'latest'}'"
        )

        command = [
            sys.executable,
            "-m",
            "guarddog",
            "npm",
            "scan",
            dep_name,
            "--output-format",
            "json",
        ]
        for metadata_rule in self._metadata_rule_names():
            command += ["--exclude-rules", metadata_rule]
        if resolved_version:
            command += ["--version", resolved_version]

        sandbox_choice = os.environ.get("GUARDDOG_SUBSCAN_SANDBOX")
        if sandbox_choice == "1":
            command.append("--sandbox")
        elif sandbox_choice == "0":
            command.append("--no-sandbox")

        log.debug(f"[{self.name}] Scanning new dependency: {' '.join(command)}")
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=SUBSCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            log.debug(f"Timed out scanning new dependency {dep_name}")
            return None

        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            log.debug(
                f"Could not parse scan output for new dependency {dep_name}: "
                f"{completed.stderr.strip()}"
            )
            return None

        risk_score = result.get("risk_score") or {}
        score = risk_score.get("score")
        if score is None:
            return None

        return DependencyRisk(
            version=resolved_version or "latest",
            score=float(score),
            label=risk_score.get("label", ""),
            matched_rules=self._matched_rules(result),
        )

    @staticmethod
    def _matched_rules(result: dict) -> List[str]:
        """Distinct rule names that flagged the dependency, in first-seen order.

        Prefers the threat rules behind each risk; falls back to any metadata rule
        that produced a message when no source-code risks were formed."""
        rules: list[str] = []
        for risk in result.get("risks", []):
            rule = risk.get("threat_rule")
            if rule and rule not in rules:
                rules.append(rule)
        if not rules:
            for rule, message in (result.get("results") or {}).items():
                if message and rule not in rules:
                    rules.append(rule)
        return rules

    @staticmethod
    def _metadata_rule_names() -> List[str]:
        """All npm metadata rule names, excluded from the dependency sub-scan so it
        runs source-code rules only. Imported lazily to avoid a circular import."""
        from guarddog.analyzer.metadata import get_metadata_detectors
        from guarddog.ecosystems import ECOSYSTEM

        return list(get_metadata_detectors(ECOSYSTEM.NPM).keys())
