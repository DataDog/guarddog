""" Empty Information Detector

Detects if a package contains an empty description
"""
from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class IntegrityMismatch(Detector):
    """This package contains files that have been tampered with between the source repository and the package CDN"""
    RULE_NAME = "repository_integrity_mismatch"

    @abstractmethod
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        pass
