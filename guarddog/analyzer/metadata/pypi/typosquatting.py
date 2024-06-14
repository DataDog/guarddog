import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import requests
import packaging.utils

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

log = logging.getLogger("guarddog")


class PypiTyposquatDetector(TyposquatDetector):
    """
    Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 1000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (list): list of top 5000 downloaded packages from PyPI
    """

    def _get_top_packages(self) -> set:
        """
        Gets the package information of the top 5000 most downloaded PyPI packages

        Returns:
            set: set of package data in the format:
                {
                    ...
                    {
                        download_count: ...
                        project: <package-name>
                    }
                    ...
                }
        """

        popular_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

        top_packages_filename = "top_pypi_packages.json"
        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "resources"))

        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        top_packages_information = None

        if top_packages_filename in os.listdir(resources_dir):
            update_time = datetime.fromtimestamp(os.path.getmtime(top_packages_path))

            if datetime.now() - update_time <= timedelta(days=30):
                with open(top_packages_path, "r") as top_packages_file:
                    top_packages_information = json.load(top_packages_file)["rows"]

        if top_packages_information is None:
            response = requests.get(popular_packages_url).json()
            with open(top_packages_path, "w+") as f:
                json.dump(response, f, ensure_ascii=False, indent=4)

            top_packages_information = response["rows"]

        def get_safe_name(package):
            return packaging.utils.canonicalize_name(package["project"])

        return set(map(get_safe_name, top_packages_information))

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, Optional[str]]:
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
        log.debug(f"Running typosquatting heuristic on PyPI package {name}")
        normalized_name = packaging.utils.canonicalize_name(package_info["info"]["name"])
        similar_package_names = self.get_typosquatted_package(normalized_name)
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(similar_package_names)
        return False, None


if __name__ == "__main__":
    # update top_pypi_packages.json
    PypiTyposquatDetector()._get_top_packages()
