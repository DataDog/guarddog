import json
import os
from datetime import datetime, timedelta
from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION
import requests


class NPMTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 5000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top 5000 most popular packages from npm
    """

    def _get_top_packages(self) -> set:

        popular_packages_url = (
            "https://github.com/LeoDog896/npm-rank/releases/download/latest/raw.json"
        )

        top_packages_filename = "top_npm_packages.json"

        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        top_packages_information = None

        if top_packages_filename in os.listdir(resources_dir):
            update_time = datetime.fromtimestamp(os.path.getmtime(top_packages_path))

            if datetime.now() - update_time <= timedelta(days=30):
                with open(top_packages_path, "r") as top_packages_file:
                    top_packages_information = json.load(top_packages_file)

        if top_packages_information is None:
            response = requests.get(popular_packages_url).json()
            top_packages_information = list([i["name"] for i in response[0:5000]])
            with open(top_packages_path, "w+") as f:
                json.dump(top_packages_information, f, ensure_ascii=False, indent=4)

        return set(top_packages_information)

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
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
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(
                similar_package_names
            )
        return False, None


if __name__ == "__main__":
    # update top_npm_packages.json
    NPMTyposquatDetector()._get_top_packages()
