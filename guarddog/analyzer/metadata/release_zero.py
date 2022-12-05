""" Empty Information Detector

Detects when a package has its latest release version to 0.0.0
"""


from guarddog.analyzer.metadata.detector import Detector


class ReleaseZeroDetector(Detector):
    def __init__(self) -> None:
        super()

    def detect(self, package_info) -> tuple[bool, str]:
        return (package_info["info"]['version'] in ['0.0.0', '0.0'],
                "The package has its latest release version to 0.0.0")
