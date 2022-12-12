import json
import os
from datetime import datetime, timedelta
from itertools import permutations
from typing import Optional
from packaging.utils import canonicalize_name
import requests

from guarddog.analyzer.metadata.detector import Detector


class TyposquatDetector(Detector):
    """
    Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 1000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (list): list of top 5000 downloaded packages from PyPI
    """

    RULE_NAME = "typosquatting"
    MESSAGE_TEMPLATE = "This package closely ressembles the following package names, and might be a typosquatting " \
                       "attempt: %s"

    def __init__(self) -> None:
        self.popular_packages = self._get_top_packages()  # Find top PyPI packages
        super().__init__()  # Call constructor

    def _get_top_packages(self) -> list:
        """
        Gets the package information of the top 5000 most downloaded PyPI packages

        Returns:
            list: list of package data in the format:
                [
                    ...
                    {
                        download_count: ...
                        project: <package-name>
                    }
                    ...
                ]
        """

        popular_packages_url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

        top_packages_filename = "top_pypi_packages.json"
        resources_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "resources"))
        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        top_packages_information = None

        if top_packages_filename in os.listdir(resources_dir):
            update_time = datetime.fromtimestamp(os.path.getmtime(top_packages_path))

            if datetime.now() - update_time <= timedelta(days=30):
                top_packages_file = open(top_packages_path, "r")
                top_packages_information = json.load(top_packages_file)["rows"]

        if top_packages_information is None:
            response = requests.get(popular_packages_url).json()
            with open(top_packages_path, "w+") as f:
                json.dump(response, f, ensure_ascii=False, indent=4)

            top_packages_information = response["rows"]

        def get_safe_name(package):
            return canonicalize_name(package["project"])

        return list(map(get_safe_name, top_packages_information))

    def _is_distance_one_Levenshtein(self, name1, name2) -> bool:
        """
        Returns True if two names have a Levenshtein distance of one

        Args:
            name1 (str): first name
            name2 (str): second name

        Returns:
            bool: True if within distance one
        """

        if abs(len(name1) - len(name2)) > 1:
            return False

        # Addition to name2
        if len(name1) > len(name2):
            for i in range(len(name1)):
                if name1[:i] + name1[i + 1:] == name2:
                    return True

        # Addition to name1
        elif len(name2) > len(name1):
            for i in range(len(name2)):
                if name2[:i] + name2[i + 1:] == name1:
                    return True

        # Edit character
        else:
            for i in range(len(name1)):
                if name1[:i] + name1[i + 1:] == name2[:i] + name2[i + 1:]:
                    return True

        return False

    def _is_swapped_typo(self, name1, name2) -> bool:
        """
        Returns true is two names are adjacent swaps of each other

        Args:
            name1 (str): first name
            name2 (str): second name

        Returns:
            bool: True if adjacent swaps
        """

        if len(name1) == len(name2):
            for i in range(len(name1) - 1):
                swapped_name1 = name1[:i] + name1[i + 1] + name1[i] + name1[i + 2:]
                if swapped_name1 == name2:
                    return True

        return False

    def _generate_permutations(self, package_name) -> list[str]:
        """
        Generates all permutations of hyphenated terms of a package

        Args:
            package_name (str): name of package

        Returns:
            list[str]: permutations of package_name
        """

        if "-" not in package_name:
            return []

        components = package_name.split("-")
        hyphen_permutations = ["-".join(p) for p in permutations(components)]

        return hyphen_permutations

    def _is_length_one_edit_away(self, package1, package2) -> bool:
        """
        Returns True if two packages are within a distance one typo edit
        (either within a Levenshtein distance of one or an adjacent swap edit)

        Args:
            package1 (str): first package name
            package2 (str): second package name

        Returns:
            bool: True
        """

        return self._is_distance_one_Levenshtein(package1, package2) or self._is_swapped_typo(package1, package2)

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
            replaced_form = terms[:i] + [confused_term] + terms[i + 1:]
            removed_form = terms[:i] + terms[i + 1:]

            for form in (replaced_form, removed_form):
                confused_forms.append("-".join(form))

        return confused_forms

    def get_typosquatted_package(self, package_name) -> list[str]:
        """
        Gets all legitimate packages that a given name
        is possibly typosquatting from

        Checks for Levenshtein distance, permutations, and confused terms
        against the top 5000 most downloaded PyPI packages

        Args:
            package_name (str): name of package

        Returns:
            list[str]: names of packages that <package_name> could be
            typosquatting from
        """

        # Get permuted typosquats for normalized and confused names
        normalized_name = canonicalize_name(package_name)

        if normalized_name in self.popular_packages:
            return []

        # Go through popular packages and find length one edit typosquats
        typosquatted = set()
        for popular_package in self.popular_packages:
            if self._is_length_one_edit_away(normalized_name, popular_package):
                typosquatted.add(popular_package)

            alternate_popular_names = self._get_confused_forms(popular_package)
            swapped_popular_names = self._generate_permutations(popular_package)

            for name in alternate_popular_names + swapped_popular_names:
                if self._is_length_one_edit_away(normalized_name, name):
                    typosquatted.add(popular_package)

        return list(typosquatted)

