import logging
from typing import Optional

import packaging.utils

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector

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
        Gets the package information of the top 5000 most downloaded PyPI packages.
        Uses the base class implementation with PyPI-specific parameters.
        """
        packages = self._get_top_packages_with_refresh(
            packages_filename="top_pypi_packages.json",
            popular_packages_url="https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
            refresh_days=30,
        )

        # Apply canonicalization to PyPI package names
        return set(map(self._canonicalize_name, packages))

    def _extract_package_names(self, data: dict | list | None) -> list | None:
        """
        Extract package names from PyPI data structure.
        PyPI data has format: {"rows": [{"project": "name", "download_count": ...}, ...]}
        """
        if data is None:
            return None

        if isinstance(data, dict) and "rows" in data:
            return [row["project"] for row in data["rows"]]

        return None

    @staticmethod
    def _canonicalize_name(package_name: str) -> str:
        """Canonicalize PyPI package names according to PEP 503."""
        return packaging.utils.canonicalize_name(package_name)

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
