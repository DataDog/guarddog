""" Empty Information Detector

Detects if a package contains an empty description
"""


from guarddog.analyzer.metadata.detector import Detector


class EmptyInfoDetector(Detector):
    """
    Detector for packages with empty information.
    """

    def __init__(self) -> None:
        super(Detector)

    def detect(self, package_info) -> bool:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package has an empty description

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            bool: True if package description is empty
        """

        sanitized_description = package_info["info"]["description"].strip()
        return len(sanitized_description) == 0
