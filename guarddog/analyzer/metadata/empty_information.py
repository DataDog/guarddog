""" Empty Information Detector

Detects if a package contains an empty description
"""

from guarddog.analyzer.metadata.detector import Detector


def get_info(ecosystem: str, package_info: dict) -> str:
    match ecosystem:
        case 'pypi':  # FIXME: ecosystem names in a const
            return package_info["info"]["description"].strip()
        case 'npm':
            return package_info["description"]
    raise NotImplementedError(f"unsupported ecosystem {ecosystem}")


class EmptyInfoDetector(Detector):
    """
    Detector for packages with empty information.
    """

    def detect(self, package_info, ecosystem: str) -> tuple[bool, str]:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package has an empty description

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            bool: True if package description is empty
        """

        sanitized_description = get_info(ecosystem, package_info)
        return len(sanitized_description) == 0, 'This package has an empty description on PyPi'
