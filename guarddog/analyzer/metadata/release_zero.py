""" Empty Information Detector

Detects when a package has its latest release version to 0.0.0
"""
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class ReleaseZeroDetector(Detector):

    def detect(self, package_info, ecosystem: str, path: Optional[str] = None) -> tuple[bool, str]:
        if ecosystem == 'pypi':
            return (package_info["info"]["version"] in ["0.0.0", "0.0"],
                    "The package has its latest release version to 0.0.0")
        if ecosystem == 'npm':
            if package_info["dist-tags"]["latest"] in ["0.0.0", "0.0", "0"]:
                return True, "The package has its latest release version to 0.0.0"
            return False, ""
        raise NotImplementedError(f"Not implemented for ecosystem {ecosystem}")
