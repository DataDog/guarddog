from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector


class NPMTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 5000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top 5000 most popular packages from npm
    """

    def _get_top_packages(self) -> set:
        """
        Gets the top 8000 most popular NPM packages.
        Uses the base class implementation with NPM-specific parameters.
        """
        return self._get_top_packages_with_refresh(
            packages_filename="top_npm_packages.json",
            popular_packages_url="https://github.com/LeoDog896/npm-rank/releases/download/latest/raw.json",
            refresh_days=30,
        )

    def _extract_package_names(self, data: dict | list | None) -> list | None:
        """
        Extract package names from NPM data structure.

        Network response format: [{"name": "package-name", ...}, ...]
        Local file format: ["package-name", "package-name", ...]

        This method handles both formats and limits to top 8000 packages.
        """
        if data is None:
            return None

        # If data is already a list of strings (local file format)
        if isinstance(data, list) and len(data) > 0:
            if isinstance(data[0], str):
                return data

            # If data is list of dicts (network response format)
            if isinstance(data[0], dict) and "name" in data[0]:
                return [item["name"] for item in data[0:8000]]

        return None

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

    def _get_confused_forms(self, package_name) -> list:
        """Gets confused terms for npm packages.
        Currently, there are no confused terms for npm packages.
        """
        return []


if __name__ == "__main__":
    # update top_npm_packages.json
    NPMTyposquatDetector()._get_top_packages()
