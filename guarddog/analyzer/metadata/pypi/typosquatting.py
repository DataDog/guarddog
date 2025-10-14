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

        popular_packages_url = (
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
        )

        top_packages_filename = "top_pypi_packages.json"
        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)
        top_packages_information = self._get_top_packages_local(top_packages_path)
        top_packages_information = top_packages_information["rows"]

        if self._file_is_expired(top_packages_path, days=30):
            new_information = self._get_top_packages_network(popular_packages_url)
            if new_information is not None:
                top_packages_information = new_information["rows"]

                with open(top_packages_path, "w+") as f:
                    json.dump(new_information, f, ensure_ascii=False, indent=4)

        return set(map(self.get_safe_name, top_packages_information))

    @staticmethod
    def get_safe_name(package):
        return packaging.utils.canonicalize_name(package["project"])

    def _file_is_expired(self, path: str, days: int) -> bool:
        try:
            update_time = datetime.fromtimestamp(os.path.getmtime(path))
            return datetime.now() - update_time > timedelta(days=days)
        except FileNotFoundError:
            pass # just skip

    def _get_top_packages_local(self, path: str) -> list[dict]:
        try:
            with open(path, "r") as f:
                result = json.load(f)
                return result
        except FileNotFoundError:
            log.error(f"File not found: {path}")

    def _get_top_packages_network(self, url: tuple[str]) -> list[dict]:
        try:
            response = requests.get(url)
            response.raise_for_status()

            response_data = response.json()
            result = response_data

            return result
        except json.JSONDecodeError:
            log.error(f"Couldn`t convert to json: \"{response.text}\"")
        except requests.exceptions.RequestException as e:
            log.error(f"Network error: {e}")

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
        log.debug(f"Running typosquatting heuristic on PyPI package {name}")
        normalized_name = packaging.utils.canonicalize_name(
            package_info["info"]["name"]
        )
        similar_package_names = self.get_typosquatted_package(normalized_name)
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(
                similar_package_names
            )
        return False, None

    def _get_confused_forms(self, package_name) -> list:
        """
        Gets confused terms for python packages
        Confused terms are:
            - py to python swaps (or vice versa)
            - the removal of py/python terms

        Args:
            package_name (str): name of the package

        Returns:
            list: list of confused terms
        """

        confused_forms = []

        terms = package_name.split("-")

        # Detect swaps like python-package -> py-package
        for i in range(len(terms)):
            confused_term = None

            if "python" in terms[i]:
                confused_term = terms[i].replace("python", "py")
            elif "py" in terms[i]:
                confused_term = terms[i].replace("py", "python")
            else:
                continue

            # Get form when replacing or removing py/python term
            replaced_form = terms[:i] + [confused_term] + terms[i + 1 :]
            removed_form = terms[:i] + terms[i + 1 :]

            for form in (replaced_form, removed_form):
                confused_forms.append("-".join(form))

        return confused_forms


if __name__ == "__main__":
    # update top_pypi_packages.json
    PypiTyposquatDetector()._get_top_packages()
