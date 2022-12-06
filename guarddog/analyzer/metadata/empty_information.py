""" Empty Information Detector

Detects if a package contains an empty description
"""
import os.path
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


MESSAGE = "This package has an empty description on PyPi"


class EmptyInfoDetector(Detector):
    """
    Detector for packages with empty information.
    """

    def detect(self, package_info, ecosystem: str, path: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package has an empty description

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            bool: True if package description is empty
        """
        if ecosystem == "pypi":
            return len(package_info["info"]["description"].strip()) == 0, MESSAGE

        if ecosystem == "npm" and path is not None:
            package_path = os.path.join(path, "package")
            content = os.listdir(package_path)
            return "README.md" not in content, MESSAGE

        raise NotImplementedError(f"unsupported ecosystem {ecosystem}")
