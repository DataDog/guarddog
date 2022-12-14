from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector


class PypiTyposquatDetector(TyposquatDetector):
    """
    Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 1000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (list): list of top 5000 downloaded packages from PyPI
    """

    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Uses a package's information from PyPI's JSON API to determine the
        package is attempting a typosquatting attack

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Returns:
            list[str]: names of packages that <package_name> could be
            typosquatting from
            @param **kwargs:
        """
        similar_package_names = self.get_typosquatted_package(package_info["info"]["name"])
        if len(similar_package_names) > 0:
            return True, "This package closely resembles the following package names, and might be a typosquatting " \
                         "attempt: " + ", ".join(similar_package_names)

        return False, None
