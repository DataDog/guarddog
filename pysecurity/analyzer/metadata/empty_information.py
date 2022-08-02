""" Typosquatting Detector

Detects if a package name is a typosquat of one of the top 1000 packages.
Checks for distance one Levenshtein, one-off character swaps, permutations
around hyphens, and substrings.
"""


from pysecurity.analyzer.metadata.detector import Detector


class EmptyInfoDetector(Detector):
    def __init__(self) -> None:
        super(Detector)
    
    
    def detect(self, package_info) -> list[str]:
        return len(package_info["info"]["description"]) == 0