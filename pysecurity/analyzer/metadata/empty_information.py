""" Empty Information Detector

Detects if a package contains an empty description
"""


from pysecurity.analyzer.metadata.detector import Detector


class EmptyInfoDetector(Detector):
    def __init__(self) -> None:
        super(Detector)
    
    
    def detect(self, package_info) -> list[str]:
        return len(package_info["info"]["description"]) == 0