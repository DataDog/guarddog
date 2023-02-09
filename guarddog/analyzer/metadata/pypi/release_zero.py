""" Empty Information Detector

Detects when a package has its latest release version to 0.0.0
"""
import logging
from typing import Optional

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector

log = logging.getLogger("guarddog")


class PypiReleaseZeroDetector(ReleaseZeroDetector):

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        log.debug(f"Running zero version heuristic on PyPI package {name} version {version}")
        return (package_info["info"]["version"] in ["0.0.0", "0.0"],
                ReleaseZeroDetector.MESSAGE_TEMPLATE % package_info["info"]["version"])
