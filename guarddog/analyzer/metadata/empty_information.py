""" Empty Information Detector

Detects if a package contains an empty description
"""
from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

MESSAGE = "This package has an empty description on PyPi"


class EmptyInfoDetector(Detector):
    """
    Detector for packages with empty information.
    """
    MESSAGE_TEMPLATE = "This package has an empty description on %s"
    RULE_NAME = "empty_information"

    @abstractmethod
    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package has an empty description

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            bool: True if package description is empty
        """
        pass
