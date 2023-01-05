import json
import os
from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector


class NPMTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 5000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (list): list of top 5000 downloaded packages from npm
    """

    def _get_top_packages(self) -> list:
        top_packages_filename = "top_npm_packages.json"
        resources_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "resources"))
        with open(os.path.join(resources_dir, top_packages_filename)) as file:
            top_packages_data = json.load(file)

        return list(map(lambda x: x["project"], top_packages_data))

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

        similar_package_names = self.get_typosquatted_package(package_info["name"])
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(similar_package_names)
        return False, None
