"""Install Scripts Appearance Detector

A package's `preinstall`, `install`, and `postinstall` lifecycle scripts can
execute arbitrary commands during dependency installation — older npm versions
run them automatically, while newer npm versions may require approval — which
makes them a primary execution vector for malicious packages. Most established packages never use them: their first
appearance on a package with an install-script-free history is a strong drift
signal, seen in worm-style compromises where a hijacked release adds a
`preinstall` payload to a package that never ran code at install time.

A package whose earlier versions already used install scripts is not flagged —
plenty of legitimate packages (native builds, postinstall messages) carry them
for their whole life. Only the transition from an established script-free
baseline to a script-bearing version counts.

The baseline must be established: at least ``MIN_BASELINE_VERSIONS`` earlier
versions, all script-free, are required before the appearance is flagged. A
brand-new package that ships install scripts from its first release is out of
scope for a history-based signal (other rules cover new packages).

The overlap with `threat-npm-preinstall-script` is intentional: that
source-code rule flags any non-empty `preinstall`, while this detector flags
the historical first appearance of `preinstall`, `install`, or `postinstall`.
A lifelong `preinstall` trips the existing source rule but never this
detector.
"""

import logging
from typing import Optional

from semantic_version import Version  # type: ignore

from guarddog.analyzer.metadata.detector import Detector
from guarddog.utils.npm import published_versions_before

log = logging.getLogger("guarddog")

# Install-time lifecycle scripts tracked for historical appearance.
INSTALL_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall")

# Earlier script-free versions required before an appearance counts as a break
# from an established baseline rather than a young package finding its shape.
MIN_BASELINE_VERSIONS = 3


def _parse_semver(version: str) -> Optional[Version]:
    try:
        return Version(version)
    except ValueError:
        return None


class NPMInstallScriptsAppearDetector(Detector):
    """Detects a version that introduces install-time lifecycle scripts on a
    package whose published history never used them.

    The scanned version's `scripts` field is checked first: if it declares no
    `preinstall`/`install`/`postinstall` entry there is nothing to flag. If it
    does, the package's publish history (ordered by the registry `time` map) is
    walked: any earlier version that already carried an install-time script —
    prereleases included — means this is not a first appearance, and fewer than
    MIN_BASELINE_VERSIONS earlier script-free versions means the baseline is
    too short to call it a break."""

    def __init__(self):
        super().__init__(
            name="install_scripts_appear",
            description="Identify a version that adds npm install-time lifecycle "
            "scripts (preinstall/install/postinstall) to a package whose earlier "
            "versions never used them. Install scripts appearing on an established "
            "script-free package are a common malicious-takeover vector: they can "
            "execute arbitrary commands during dependency installation (older npm "
            "versions run them automatically; newer npm versions may require "
            "approval).",
            identifies="threat.metadata.install-scripts-appear",
            severity="medium",
            mitre_tactics="execution",
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

        current_scripts = self._install_scripts(versions.get(current_version, {}))
        if not current_scripts:
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' declares no "
                f"install-time scripts; nothing to flag"
            )
            return False, None

        baseline = 0
        for earlier_version in published_versions_before(package_info, current_version):
            if not self._precedes_in_release_order(earlier_version, current_version):
                continue
            if self._install_scripts(versions.get(earlier_version, {})):
                log.debug(
                    f"[{self.name}] '{package_name}@{earlier_version}' already used "
                    f"install-time scripts; not a first appearance"
                )
                return False, None
            baseline += 1

        if baseline < MIN_BASELINE_VERSIONS:
            log.debug(
                f"[{self.name}] '{package_name}@{current_version}' has only "
                f"{baseline} earlier script-free version(s); baseline too short"
            )
            return False, None

        script_list = ", ".join(sorted(current_scripts))
        log.debug(
            f"[{self.name}] '{package_name}@{current_version}' introduces "
            f"install-time scripts ({script_list}) over {baseline} script-free "
            f"earlier versions; flagging"
        )
        return True, (
            f"Version {current_version} adds install-time lifecycle scripts "
            f"({script_list}) to a package whose {baseline} earlier published "
            f"versions never used them. These scripts can execute arbitrary commands "
            f"during dependency installation (automatically on older npm versions), "
            f"and their first appearance on an established script-free package is "
            f"a common malicious-takeover vector."
        )

    @staticmethod
    def _install_scripts(version_info: dict) -> set:
        """The install-time lifecycle script names a version declares."""
        scripts = version_info.get("scripts") or {}
        return {s for s in INSTALL_LIFECYCLE_SCRIPTS if scripts.get(s)}

    @staticmethod
    def _precedes_in_release_order(candidate: str, current_version: str) -> bool:
        """Whether `candidate` belongs to the history the current version extends.

        A version published earlier in time still belongs to a later release line
        when it is semver-greater, e.g. a `8.0.0-alpha` published before a `7.8.2`
        maintenance patch: its script usage is not part of the maintenance line's
        history. Prereleases of the current line DO count: a script introduced in
        `2.0.0-beta.1` is prior history for `2.0.0`, not a first appearance.
        """
        current_semver = _parse_semver(current_version)
        candidate_semver = _parse_semver(candidate)
        if current_semver is None or candidate_semver is None:
            # npm requires valid semver, so this is unreachable in practice; fall
            # back to publish order rather than silently dropping the version.
            return True
        return candidate_semver < current_semver
