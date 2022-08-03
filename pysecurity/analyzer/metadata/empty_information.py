""" Empty Information Detector

Detects if a package contains an empty description
"""


from pysecurity.analyzer.metadata.detector import Detector


class EmptyInfoDetector(Detector):
    def __init__(self) -> None:
        super(Detector)
    
    
    def detect(self, package_info) -> list[str]:
        sanitized_description = package_info["info"]["description"].split()
        return len(sanitized_description) == 0