import abc
import json
import logging
import os
import time
from datetime import datetime, timedelta
from itertools import permutations
from typing import Optional

import requests

from guarddog.analyzer.metadata.detector import Detector
from guarddog.utils.config import TOP_PACKAGES_CACHE_LOCATION

log = logging.getLogger("guarddog")


class TyposquatDetector(Detector):
    MESSAGE_TEMPLATE = (
        "This package closely resembles the following package names, and might be a typosquatting "
        "attempt: %s"
    )

    def __init__(self) -> None:
        self.popular_packages = self._get_top_packages()  # Find top PyPI packages
        super().__init__(
            name="typosquatting",
            description="Identify packages that are named closely to an highly popular package",
        )

    @abc.abstractmethod
    def _get_top_packages(self) -> set:
        """
        Subclasses should implement this to return a set of top package names.

        For simple implementations without network refresh, override this directly.
        For implementations with network refresh, use _get_top_packages_with_refresh().
        """
        pass

    def _get_top_packages_with_refresh(
        self,
        packages_filename: str,
        popular_packages_url: Optional[str] = None,
        refresh_days: int = 30,
    ) -> set:
        """
        Common implementation for getting top packages with optional network refresh.

        Args:
            packages_filename: Name of the JSON file (e.g., "top_pypi_packages.json")
            popular_packages_url: URL to fetch fresh package data. If None, refresh is disabled.
            refresh_days: Number of days before file is considered expired

        Returns:
            set: Set of package names
        """
        resources_dir = TOP_PACKAGES_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "resources")
            )

        top_packages_path = os.path.join(resources_dir, packages_filename)
        log.debug(f"Loading cache from: {top_packages_path}")

        cache_data = self._load_cache_file(top_packages_path)

        if cache_data:
            log.debug(f"Cache loaded successfully with keys: {list(cache_data.keys())}")
        else:
            log.debug("Cache is empty or invalid")

        top_packages_information = cache_data.get("packages") if cache_data else None

        # Enable refresh if URL is provided
        enable_refresh = popular_packages_url is not None
        is_expired = self._cache_is_expired(cache_data, days=refresh_days)
        log.debug(
            f"Cache expired check: {is_expired} (refresh enabled: {enable_refresh})"
        )

        if enable_refresh and is_expired and popular_packages_url is not None:
            log.info(
                f"Cache is expired, attempting to refresh from: {popular_packages_url}"
            )
            new_response_data = self._get_top_packages_network_raw(popular_packages_url)
            if new_response_data is not None:
                log.debug("Downloaded new data, extracting package names")
                top_packages_information = self._extract_package_names(
                    new_response_data
                )

                # Save with new standardized format
                cache_data = {
                    "downloaded_timestamp": int(time.time()),
                    "packages": top_packages_information,
                }

                if top_packages_information is not None:
                    log.info(
                        f"Saving refreshed cache with {len(top_packages_information)} packages to {top_packages_path}"
                    )
                with open(top_packages_path, "w+") as f:
                    json.dump(cache_data, f, ensure_ascii=False, indent=4)
            else:
                log.warning(
                    f"Failed to download new cache data from {popular_packages_url}"
                )

        if top_packages_information is None:
            return set()

        return set(top_packages_information)

    def _cache_is_expired(self, cache_data: dict | None, days: int) -> bool:
        """
        Check if cache data is expired based on downloaded_timestamp.

        Args:
            cache_data: Cache dictionary with 'downloaded_timestamp' key
            days: Number of days before cache is considered expired

        Returns:
            bool: True if expired or timestamp missing, False otherwise
        """
        if cache_data is None:
            log.debug("Cache is expired: cache_data is None")
            return True

        timestamp = cache_data.get("downloaded_timestamp")
        if timestamp is None:
            # Missing timestamp, consider expired
            log.debug("Cache is expired: missing 'downloaded_timestamp' field")
            return True

        try:
            download_time = datetime.fromtimestamp(timestamp)
            age = datetime.now() - download_time
            is_expired = age > timedelta(days=days)
            log.debug(
                f"Cache age: {age.days} days, threshold: {days} days, expired: {is_expired}"
            )
            return is_expired
        except (ValueError, OSError) as e:
            # Invalid timestamp
            log.debug(f"Cache is expired: invalid timestamp {timestamp} - {e}")
            return True

    def _load_cache_file(self, path: str) -> dict | None:
        """
        Load cache data from local JSON file.

        Expected format: {"downloaded_timestamp": epoch, "packages": [...]}

        If the file doesn't match this format, it will be considered invalid
        and trigger a refresh to download data in the correct format.

        Args:
            path: Path to the JSON file

        Returns:
            dict: Cache data with 'packages' and 'downloaded_timestamp', or None if invalid
        """
        try:
            with open(path, "r") as f:
                result = json.load(f)

                # Validate new format structure
                if (
                    isinstance(result, dict)
                    and "packages" in result
                    and "downloaded_timestamp" in result
                ):
                    # Validate that packages is a list
                    if isinstance(result["packages"], list):
                        return result
                    else:
                        log.warning(
                            f"Invalid cache format in {path}: 'packages' must be a list. Will trigger refresh."
                        )
                        return None

                # File doesn't have the correct format - invalidate it
                log.info(
                    f"Cache file {path} has old or invalid format. Will trigger refresh to new format."
                )
                return None

        except FileNotFoundError:
            log.debug(f"Cache file not found: {path}")
            return None
        except json.JSONDecodeError:
            log.error(f"Invalid JSON in file: {path}")
            return None

    def _get_top_packages_network_raw(self, url: str) -> dict | list | None:
        """
        Fetch the complete response data from the network.
        Returns the full JSON structure to preserve format when saving.

        Args:
            url: URL to fetch package data from

        Returns:
            dict | list: Full response data or None on error
        """
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except json.JSONDecodeError:
            log.error(f'Couldn\'t convert to json: "{response.text}"')
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Network error: {e}")
            return None

    def _extract_package_names(self, data: dict | list | None) -> list | None:
        """
        Extract package names from the raw data structure.

        Override this method in subclasses if the data format is specific to the ecosystem.
        Default implementation assumes data is already a list of package names.

        Args:
            data: Raw data from JSON file or network response

        Returns:
            list: List of package names or None
        """
        if data is None:
            return None

        # Default: assume data is already a list
        if isinstance(data, list):
            return data

        # If it's a dict, subclasses should override this method
        return None

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
                if name1[:i] + name1[i + 1 :] == name2:
                    return True

        # Addition to name1
        elif len(name2) > len(name1):
            for i in range(len(name2)):
                if name2[:i] + name2[i + 1 :] == name1:
                    return True

        # Edit character
        else:
            for i in range(len(name1)):
                if name1[:i] + name1[i + 1 :] == name2[:i] + name2[i + 1 :]:
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
                swapped_name1 = name1[:i] + name1[i + 1] + name1[i] + name1[i + 2 :]
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

        return self._is_distance_one_Levenshtein(
            package1, package2
        ) or self._is_swapped_typo(package1, package2)

    @abc.abstractmethod
    def _get_confused_forms(self, package_name) -> list:
        pass

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

        if package_name in self.popular_packages:
            return []

        # Go through popular packages and find length one edit typosquats
        typosquatted = set()
        for popular_package in self.popular_packages:
            if self._is_length_one_edit_away(package_name, popular_package):
                typosquatted.add(popular_package)

            alternate_popular_names = self._get_confused_forms(popular_package)
            swapped_popular_names = self._generate_permutations(popular_package)

            for name in alternate_popular_names + swapped_popular_names:
                if self._is_length_one_edit_away(package_name, name):
                    typosquatted.add(popular_package)

        return list(typosquatted)
