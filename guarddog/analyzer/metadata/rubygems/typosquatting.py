import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import requests

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

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
        popular_packages_url = (
            "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/"
            "package_names?critical=true&per_page=1000"
        )

        top_packages_filename = "top_rubygems_packages.json"
        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "resources")
            )

        top_packages_path = os.path.join(resources_dir, top_packages_filename)
        top_packages_information = self._get_top_packages_local(top_packages_path)

        if self._file_is_expired(top_packages_path, days=30):
            new_information = self._get_top_packages_network(popular_packages_url)
            if new_information is not None:
                top_packages_information = new_information

                with open(top_packages_path, "w+") as f:
                    json.dump(new_information, f, ensure_ascii=False, indent=4)

        if top_packages_information is None:
            return set()
        return set(top_packages_information)

    def _file_is_expired(self, path: str, days: int) -> bool:
        try:
            update_time = datetime.fromtimestamp(os.path.getmtime(path))
            return datetime.now() - update_time > timedelta(days=days)
        except FileNotFoundError:
            return True

    def _get_top_packages_local(self, path: str) -> list | None:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            log.debug(f"File not found: {path}")
            return None

    def _get_top_packages_network(self, url: str) -> list | None:
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except json.JSONDecodeError:
            log.error(f'Could not parse JSON from: "{response.text}"')
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Network error: {e}")
            return None

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
