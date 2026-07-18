"""Provenance Regression Detector

npm records a `dist.attestations` field on a version when it was published with
provenance (`npm publish --provenance` from a trusted CI flow). When a version
that previously carried attestations is followed by one that lacks them, the
publish likely happened outside the normal attested flow. That regression is the
signal this detector flags, mirroring the pattern seen in the nx compromise where
malicious versions were pushed with stolen credentials.

A package that never adopted provenance is not flagged. Absence alone is common
and legitimate; only a regression (had it, then lost it) counts.
"""

import logging
from typing import List, Optional

from guarddog.analyzer.metadata.detector import Detector

log = logging.getLogger("guarddog")

# Keys in the registry `time` object that are not version publish timestamps.
_NON_VERSION_TIME_KEYS = {"created", "modified"}


class NPMProvenanceRegressionDetector(Detector):
    """Detects a version that dropped npm provenance attestations earlier versions had.

    The scanned version's `dist.attestations` is checked first: if present, there is
    no regression. If absent, the package's publish history (ordered by the registry
    `time` map) is walked backward. Finding an earlier version that did carry
    attestations flags the package; running out of earlier versions without finding
    one means the package never used provenance, which is not a regression."""

    def __init__(self):
        super().__init__(
            name="provenance_regression",
            description="Identify a version that lost npm provenance attestations that "
            "earlier versions had. A version dropping provenance after prior versions "
            "carried it can indicate a publish made outside the normal CI-attested flow.",
            identifies="threat.npm.provenance-regression",
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

        last_attested = self._most_recent_attested_before(
            package_info, current_version
        )
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

        Publish times come from the registry `time` map; ISO 8601 timestamps sort
        lexicographically. The walk does not stop at the immediately preceding
        version: a compromise may push several unsigned releases in a row, so the
        search continues back until a version with attestations is found or the
        history is exhausted.
        """
        versions = package_info.get("versions", {})
        published = {
            v: t
            for v, t in package_info.get("time", {}).items()
            if v not in _NON_VERSION_TIME_KEYS and v in versions
        }
        current_time = published.get(current_version)
        if current_time is None:
            return None

        earlier: List[tuple] = [
            (t, v) for v, t in published.items() if t < current_time
        ]
        # Newest-first by publish time. The version-string tie-break only matters if
        # two versions share an identical timestamp, which does not happen in practice;
        # it never changes whether a package is flagged, only which version is named.
        for _, earlier_version in sorted(earlier, reverse=True):
            if self._has_attestations(versions.get(earlier_version, {})):
                return earlier_version
        return None
