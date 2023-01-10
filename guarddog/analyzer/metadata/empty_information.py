""" Empty Information Detector

Detects if a package contains an empty description
"""
from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

MESSAGE = "This package has an empty description on PyPi"


class EmptyInfoDetector(Detector):
    """This heuristic detects packages with empty documentation on the package repository.
    Such situation might be the marker of a low quality package."""

    MESSAGE_TEMPLATE = "This package has an empty description on %s"
    RULE_NAME = "empty_information"

    @abstractmethod
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package has an empty description

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            bool: True if package description is empty
            @param **kwargs:
        """
        pass
