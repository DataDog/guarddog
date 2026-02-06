import logging
from typing import Optional

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector

log = logging.getLogger("guarddog")


class RubyGemsTyposquatDetector(TyposquatDetector):
    """
    Detector for typosquatting attacks on RubyGems.
    Checks for distance one Levenshtein, one-off character swaps,
    permutations around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of critical/popular gems from ecosyste.ms
    """

    def _get_top_packages(self) -> set:
        """
        Gets the top 1000 critical RubyGems packages.
        Uses the base class implementation with RubyGems-specific parameters.
        """
        url = "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/package_names?critical=true&per_page=1000"
        return self._get_top_packages_with_refresh(
            packages_filename="top_rubygems_packages.json",
            popular_packages_url=url,
            refresh_days=30,
        )

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Uses a gem's information to determine if it's attempting
        a typosquatting attack.
        """
        gem_name = package_info.get("name", name)
        log.debug(f"Running typosquatting heuristic on RubyGems package {gem_name}")

        similar_package_names = self.get_typosquatted_package(gem_name)
        if len(similar_package_names) > 0:
            return True, TyposquatDetector.MESSAGE_TEMPLATE % ", ".join(
                similar_package_names
            )
        return False, None

    def _get_confused_forms(self, package_name) -> list:
        """
        Gets confused terms for Ruby gems.
        Confused terms are:
            - ruby to rb swaps (or vice versa)
            - the removal of ruby/rb terms
            - rails to ruby-on-rails swaps

        Args:
            package_name (str): name of the package

        Returns:
            list: list of confused terms
        """
        confused_forms = []

        terms = package_name.split("-")

        for i in range(len(terms)):
            confused_term = None

            if "ruby" in terms[i]:
                confused_term = terms[i].replace("ruby", "rb")
            elif "rb" in terms[i]:
                confused_term = terms[i].replace("rb", "ruby")
            else:
                continue

            replaced_form = terms[:i] + [confused_term] + terms[i + 1 :]
            removed_form = terms[:i] + terms[i + 1 :]

            for form in (replaced_form, removed_form):
                confused_forms.append("-".join(form))

        if package_name == "rails":
            confused_forms.append("ruby-on-rails")
        elif package_name == "ruby-on-rails":
            confused_forms.append("rails")

        return confused_forms
