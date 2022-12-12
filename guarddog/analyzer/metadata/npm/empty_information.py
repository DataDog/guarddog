""" Empty Information Detector

Detects if a package contains an empty description
"""
import os.path
from typing import Optional

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector

MESSAGE = "This package has an empty description on PyPi"


class NPMEmptyInfoDetector(EmptyInfoDetector):

    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, str]:
        if path is None:
            raise TypeError("path must be a string")
        package_path = os.path.join(path, "package")
        content = map(
            lambda x: x.lower(),
            os.listdir(package_path)
        )
        return "readme.md" not in content, EmptyInfoDetector.MESSAGE_TEMPLATE % "npm"
