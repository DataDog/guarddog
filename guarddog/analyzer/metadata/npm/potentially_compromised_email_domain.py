""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime
from typing import Optional

from dateutil import parser

from guarddog.analyzer.metadata.potentially_compromised_email_domain import PotentiallyCompromisedEmailDomainDetector

from .utils import get_email_addresses


class NPMPotentiallyCompromisedEmailDomainDetector(PotentiallyCompromisedEmailDomainDetector):
    def __init__(self):
        super().__init__("npm")

    def get_email_addresses(self, package_info: dict):
        return get_email_addresses(package_info)

    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        """
        Gets the most recent release date of a Python project

        Args:
            releases (dict): PyPI JSON API's representation field

        Returns:
            datetime: creation date of the most recent in releases
        """
        latest_release_version = package_info["dist-tags"]["latest"]
        raw_date = package_info["time"][latest_release_version]
        release_date = parser.isoparse(raw_date).replace(tzinfo=None)
        return release_date
