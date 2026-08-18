"""New Install Script Detector

Flags a version that introduces preinstall/install/postinstall scripts on a
package whose earlier versions never used them. These scripts run during
`npm install` and are a common malicious-takeover vector; most established
packages never use them.

Overlaps with `threat-npm-preinstall-script` (which flags any preinstall);
this detector only fires on the historical first appearance.
"""

import logging
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector
from guarddog.utils.npm import precedes_in_release_order, published_versions_before

log = logging.getLogger("guarddog")

# npm scripts that run during package installation.
INSTALL_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall")

# Min script-free versions before an appearance counts as a baseline break.
MIN_BASELINE_VERSIONS = 3


class NPMNewInstallScriptDetector(Detector):
    """Flags a version that adds install-time lifecycle scripts to a package
    whose earlier versions never used them."""

    def __init__(self):
        super().__init__(
            name="new_install_script",
            description="Identify a version that adds npm install-time lifecycle "
            "scripts (preinstall/install/postinstall) to a package whose earlier "
            "versions never used them. Install scripts appearing on an established "
            "script-free package are a common malicious-takeover vector: they can "
            "execute arbitrary commands during dependency installation (older npm "
            "versions run them automatically; newer npm versions may require "
            "approval).",
            identifies="threat.metadata.new-install-script",
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
            # Ignore other release lines (e.g. 8.0.0-alpha before a 7.x patch);
            # prereleases of the current line count as history.
            if not precedes_in_release_order(earlier_version, current_version):
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
