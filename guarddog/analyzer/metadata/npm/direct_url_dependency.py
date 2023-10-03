""" Direct URL Dependency Detector

Detects if a package depends on direct URL dependencies
"""
from typing import Optional
import re

from guarddog.analyzer.metadata.detector import Detector

from urllib.parse import urlparse


github_project_pattern = re.compile(r"^([\w\-\.]+)/([\w\-\.]+)")


class NPMDirectURLDependencyDetector(Detector):
    """This heuristic detects packages with direct URL dependencies.
    Dependencies fetched this way are not immutable and can be used to inject untrusted code
    or reduce the likelihood of a reproducible install."""

    def __init__(self):
        super().__init__(
            name="direct_url_dependency",
            description="Identify packages with direct URL dependencies. \
Dependencies fetched this way are not immutable and can be used to \
inject untrusted code or reduce the likelihood of a reproducible install.",
        )

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        findings = []

        for dep_name, dep_version in (
            package_info.get("versions", {})
            .get(version, {})
            .get("dependencies", {})
            .items()
        ):
            # According to npm documentation, HTTP(s) and Git are accepted URL schemes when specifying dependencies:
            # https://docs.npmjs.com/cli/v10/configuring-npm/package-json#urls-as-dependencies
            # https://docs.npmjs.com/cli/v10/configuring-npm/package-json#git-urls-as-dependencies
            if urlparse(dep_version).scheme in [
                "http",
                "https",
                "git",
                "git+ssh",
                "git+http",
                "git+https",
                "git+file",
            ]:
                findings.append(
                    f"Dependency {dep_name} refers to a direct Git or HTTP URL {dep_version}."
                )
            # According to npm documentation, Github repositories are accepted when specifying dependencies:
            # https://docs.npmjs.com/cli/v10/configuring-npm/package-json#github-urls
            elif github_project_pattern.match(dep_version):
                findings.append(
                    f"Dependency {dep_name} refers to a direct Github repository {dep_version}."
                )

        return len(findings) != 0, "\n".join(findings)
