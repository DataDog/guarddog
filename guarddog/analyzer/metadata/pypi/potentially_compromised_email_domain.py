""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""
from datetime import datetime
from typing import Optional

from dateutil import parser
from packaging import version

from guarddog.analyzer.metadata.potentially_compromised_email_domain import PotentiallyCompromisedEmailDomainDetector


class PypiPotentiallyCompromisedEmailDomainDetector(PotentiallyCompromisedEmailDomainDetector):
    def __init__(self):
        super().__init__("pypi")

    def get_email_addresses(self, package_info: dict) -> list[str]:
        author_email = package_info["info"]["author_email"]
        maintainer_email = package_info["info"]["maintainer_email"]
        email = author_email or maintainer_email
        return [email]

    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        """
        Gets the most recent release date of a Python project

        Args:
            releases (dict): PyPI JSON API's representation field

        Returns:
            datetime: creation date of the most recent in releases
        """
        releases = package_info["releases"]
        sorted_versions = sorted(
            releases.keys(), key=lambda r: version.parse(r), reverse=True
        )
        earlier_versions = sorted_versions[:-1]

        for early_version in earlier_versions:
            version_release = releases[early_version]

            if len(version_release) > 0:  # if there's a distribution for the package
                upload_time_text = version_release[0]["upload_time_iso_8601"]
                release_date = parser.isoparse(upload_time_text).replace(tzinfo=None)
                return release_date
        raise Exception("could not find release date")
