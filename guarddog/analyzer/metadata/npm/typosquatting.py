import json
import os
import time
from typing import Optional

import requests

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

_NPMS_URL = "https://api.npms.io/v2/search?q=not:unstable&size=250&from={offset}"
_TOP_N = 8000
_PAGE_SIZE = 250
_CACHE_FILE = "top_npm_packages.json"
_REFRESH_DAYS = 30


class NPMTyposquatDetector(TyposquatDetector):
    """Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 8000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (set): set of top 8000 most popular packages from npm
    """

    def _get_top_packages(self) -> set:
        resources_dir = TOP_PACKAGES_CACHE_LOCATION or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../resources")
        )
        cache_path = os.path.join(resources_dir, _CACHE_FILE)
        cache = self._load_cache_file(cache_path)

        if not self._cache_is_expired(cache, days=_REFRESH_DAYS):
            packages = (cache or {}).get("packages") or []
            return set(packages)

        packages = self._fetch_from_npms()
        if packages:
            with open(cache_path, "w+") as f:
                json.dump({"downloaded_timestamp": int(time.time()), "packages": packages}, f,
                          ensure_ascii=False, indent=4)
            return set(packages)

        # Fall back to stale cache rather than returning empty
        packages = (cache or {}).get("packages") or []
        return set(packages)

    def _fetch_from_npms(self) -> list:
        packages = []
        for offset in range(0, _TOP_N, _PAGE_SIZE):
            try:
                resp = requests.get(
                    _NPMS_URL.format(offset=offset),
                    headers={"User-Agent": "guarddog/1.0"},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                break
            batch = [obj["package"]["name"] for obj in data.get("results", [])]
            packages.extend(batch)
            if len(batch) < _PAGE_SIZE:
                break
        return packages[:_TOP_N]

    def _extract_package_names(self, data: dict | list | None) -> list | None:
        if data is None:
            return None

        # Local cache format: list of strings
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], str):
            return data

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
        Older npm packages may use uppercase letters, while new packages must be
        lowercase. Treat the lowercase form as confusingly similar so packages
        like "jsonstream" can be flagged against "JSONStream".
        """
        lowercase_package_name = package_name.lower()
        if lowercase_package_name == package_name:
            return []

        return [lowercase_package_name]


if __name__ == "__main__":
    # update top_npm_packages.json
    NPMTyposquatDetector()._get_top_packages()
