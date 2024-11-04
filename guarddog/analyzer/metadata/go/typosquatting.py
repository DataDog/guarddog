import json
import os
from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION


class GoTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks for go modules. Checks for distance one Levenshtein,
    one-off character swaps, permutations around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top 500 most popular Go packages,
          as determined by count of references across top starred repositories
    """

    def _get_top_packages(self) -> set:
        top_packages_filename = "top_go_packages.json"

        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)

        top_packages_information = None

        if top_packages_filename in os.listdir(resources_dir):
            with open(top_packages_path, "r") as top_packages_file:
                top_packages_information = json.load(top_packages_file)

        if top_packages_information is None:
            raise Exception(
                f"Could not retrieve top Go packages from {top_packages_path}")

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

        similar_package_names = self.get_typosquatted_package(name)
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

        if package_name.startswith("github.com/"):
            replaced = package_name.replace("github.com/", "gitlab.com/", 1)
            confused_forms.append(replaced)
        elif package_name.startswith("gitlab.com/"):
            replaced = package_name.replace("gitlab.com/", "github.com/", 1)
            confused_forms.append(replaced)

        terms = package_name.split("-")

        # Detect swaps like golang-package -> go-package
        for i in range(len(terms)):
            confused_term = None

            if "golang" in terms[i]:
                confused_term = terms[i].replace("golang", "go")
            elif "go" in terms[i]:
                confused_term = terms[i].replace("go", "golang")
            else:
                continue

            # Get form when replacing or removing go/golang term
            replaced_form = terms[:i] + [confused_term] + terms[i + 1:]
            removed_form = terms[:i] + terms[i + 1:]

            for form in (replaced_form, removed_form):
                confused_forms.append("-".join(form))

        return confused_forms


if __name__ == "__main__":
    # update top_npm_packages.json
    GoTyposquatDetector()._get_top_packages()
