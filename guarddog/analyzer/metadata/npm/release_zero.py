""" Empty Information Detector

Detects when a package has its latest release version to 0.0.0
"""
from typing import Optional

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector


class NPMReleaseZeroDetector(ReleaseZeroDetector):

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        return package_info["dist-tags"]["latest"] in ["0.0.0", "0.0", "0"], \
            ReleaseZeroDetector.MESSAGE_TEMPLATE % package_info["dist-tags"]["latest"]
