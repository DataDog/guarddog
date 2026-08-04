"""Provenance Regression Detector

npm records a `dist.attestations` field on a version when it was published with
provenance (`npm publish --provenance` from a trusted CI flow). When a version
that previously carried attestations is followed by one that lacks them, the
publish likely happened outside the normal attested flow. That regression is the
signal this detector flags, mirroring the pattern seen in the nx compromise where
malicious versions were pushed with stolen credentials.

A package that never adopted provenance is not flagged. Absence alone is common
and legitimate; only a regression (had it, then lost it) counts.

Evidence of prior provenance must come from a version that precedes the scanned one
in semver order, not merely in publish time. Projects routinely publish a modernized
release line from an attested CI workflow while still cutting maintenance releases of
an older line the old way, so a later-published patch of an older line is not a
regression against it.
"""

import logging
from typing import Optional

from semantic_version import Version  # type: ignore

from guarddog.analyzer.metadata.detector import Detector
from guarddog.utils.npm import published_versions_before

log = logging.getLogger("guarddog")


def _parse_semver(version: str) -> Optional[Version]:
    try:
        return Version(version)
    except ValueError:
        return None


class NPMProvenanceRegressionDetector(Detector):
    """Detects a version that dropped npm provenance attestations earlier versions had.

    The scanned version's `dist.attestations` is checked first: if present, there is
    no regression. If absent, the package's publish history (ordered by the registry
    `time` map) is walked backward. Finding an earlier version that did carry
    attestations flags the package; running out of earlier versions without finding
    one means the package never used provenance, which is not a regression.

    Only versions that also precede the scanned one in semver order count as evidence,
    and prereleases only count when the scanned version is itself a prerelease."""

    def __init__(self):
        super().__init__(
            name="provenance_regression",
            description="Identify a version that lost npm provenance attestations that "
            "earlier versions had. A version dropping provenance after prior versions "
            "carried it can indicate a publish made outside the normal CI-attested flow.",
            identifies="threat.metadata.provenance-regression",
            severity="medium",
            mitre_tactics="initial-access",
            specificity="medium",
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

        if self._has_attestations(versions.get(current_version, {})):
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' has provenance "
                f"attestations; no regression"
            )
            return False, None

        last_attested = self._most_recent_attested_before(package_info, current_version)
        if last_attested is None:
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' lacks attestations "
                f"and no earlier version had them; not a regression"
            )
            return False, None

        log.debug(
            f"[{self.name}] '{package_name}@{current_version}' lost provenance "
            f"attestations last seen on '{last_attested}'; flagging"
        )
        return True, (
            f"Version {current_version} was published without npm provenance "
            f"attestations, but the earlier version {last_attested} had them. Losing "
            f"provenance after previous versions carried it can indicate a publish made "
            f"outside the normal CI-attested flow, as seen in the nx compromise."
        )

    @staticmethod
    def _has_attestations(version_info: dict) -> bool:
        """Whether a version was published with npm provenance attestations."""
        return "attestations" in (version_info.get("dist") or {})

    def _most_recent_attested_before(
        self, package_info, current_version: str
    ) -> Optional[str]:
        """Walk earlier versions newest-first and return the first with attestations.

        The walk does not stop at the immediately preceding version: a compromise may
        push several unsigned releases in a row, so the search continues back until a
        version with attestations is found or the history is exhausted.
        """
        versions = package_info.get("versions", {})
        for earlier_version in published_versions_before(package_info, current_version):
            if not self._precedes_in_release_order(earlier_version, current_version):
                continue
            if self._has_attestations(versions.get(earlier_version, {})):
                return earlier_version
        return None

    @staticmethod
    def _precedes_in_release_order(candidate: str, current_version: str) -> bool:
        """Whether `candidate` can be evidence of provenance the current version lost.

        A version published earlier in time still belongs to a later release line when
        it is semver-greater, e.g. an attested `8.0.0-alpha` published before an
        unattested `7.8.2` maintenance patch. Such a version is not something the
        current one regressed from.

        Prereleases only count as evidence for another prerelease: a project commonly
        pipes its `next` line through attested CI before its stable line, and a stable
        release that lacks what only an alpha had has not lost anything.
        """
        current_semver = _parse_semver(current_version)
        candidate_semver = _parse_semver(candidate)
        if current_semver is None or candidate_semver is None:
            # npm requires valid semver, so this is unreachable in practice; fall back
            # to publish order rather than silently dropping the version from the walk.
            return True
        if candidate_semver.prerelease and not current_semver.prerelease:
            return False
        return candidate_semver < current_semver
