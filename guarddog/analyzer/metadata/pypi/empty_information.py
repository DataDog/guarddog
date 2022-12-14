""" Empty Information Detector

Detects if a package contains an empty description
"""
from typing import Optional

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector

MESSAGE = "This package has an empty description on PyPi"


class PypiEmptyInfoDetector(EmptyInfoDetector):
    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, str]:
        return len(package_info["info"]["description"].strip()) == 0, EmptyInfoDetector.MESSAGE_TEMPLATE % "PyPI"
