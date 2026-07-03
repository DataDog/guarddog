import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional

import packaging.utils
import requests

from guarddog.analyzer.metadata.typosquatting import TyposquatDetector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

log = logging.getLogger("guarddog")

_CLICKHOUSE_URL = "https://sql-clickhouse.clickhouse.com"
_TOP_N = 10000
_CACHE_FILE = "top_pypi_packages.json"
_REFRESH_DAYS = 30


class PypiTyposquatDetector(TyposquatDetector):
    """
    Detector for typosquatting attacks. Detects if a package name is a typosquat of one of the top 10000 packages.
    Checks for distance one Levenshtein, one-off character swaps, permutations
    around hyphens, and substrings.

    Attributes:
        popular_packages (list): list of top 15000 downloaded packages from PyPI
    """

    def _get_top_packages(self) -> set:
        resources_dir = TOP_PACKAGES_CACHE_LOCATION or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../resources")
        )
        cache_path = os.path.join(resources_dir, _CACHE_FILE)
        cache = self._load_cache_file(cache_path)

        if not self._cache_is_expired(cache, days=_REFRESH_DAYS):
            packages = (cache or {}).get("packages") or []
            return set(map(self._canonicalize_name, packages))

        packages = self._fetch_from_clickhouse()
        if packages:
            with open(cache_path, "w+") as f:
                json.dump(
                    {"downloaded_timestamp": int(time.time()), "packages": packages},
                    f,
                    ensure_ascii=False,
                    indent=4,
                )
            return set(map(self._canonicalize_name, packages))

        # Fall back to stale cache rather than returning empty
        packages = (cache or {}).get("packages") or []
        return set(map(self._canonicalize_name, packages))

    def _fetch_from_clickhouse(self) -> list:
        last_month = (datetime.now() - timedelta(days=32)).strftime("%Y-%m-01")
        sql = (
            f"SELECT SUM(count) AS download_count, project "
            f"FROM pypi.pypi_downloads_per_month "
            f"WHERE month = '{last_month}' "
            f"GROUP BY project ORDER BY download_count DESC "
            f"LIMIT {_TOP_N}"
        )
        try:
            resp = requests.post(
                _CLICKHOUSE_URL,
                params={"user": "demo", "default_format": "JSON"},
                data=sql.encode("utf-8"),
                headers={"User-Agent": "guarddog/1.0"},
                timeout=30,
            )
            resp.raise_for_status()
            return [row["project"] for row in resp.json().get("data", [])]
        except Exception as e:
            log.warning(f"Failed to fetch PyPI top packages from ClickHouse: {e}")
            return []

    def _extract_package_names(self, data: dict | list | None) -> list | None:
        if data is None:
            return None

        # Local cache format: list of strings
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], str):
            return data

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
