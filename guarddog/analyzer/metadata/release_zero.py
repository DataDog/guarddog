""" Empty Information Detector

Detects when a package has its latest release version to 0.0.0
"""

from guarddog.analyzer.metadata.detector import Detector


class ReleaseZeroDetector(Detector):

    MESSAGE_TEMPLATE = "The package has its latest release version to %s"
    RULE_NAME = "release_zero"
