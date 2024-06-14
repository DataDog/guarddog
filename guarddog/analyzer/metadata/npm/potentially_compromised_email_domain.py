""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime, timezone
from typing import Optional

from dateutil import parser

from guarddog.analyzer.metadata.potentially_compromised_email_domain import \
    PotentiallyCompromisedEmailDomainDetector

from .utils import NPM_API_MAINTAINER_EMAIL_WARNING, get_email_addresses


class NPMPotentiallyCompromisedEmailDomainDetector(
    PotentiallyCompromisedEmailDomainDetector
):
    def __init__(self):
        super().__init__("npm")

        self.description += "; " + NPM_API_MAINTAINER_EMAIL_WARNING

    def get_email_addresses(self, package_info: dict) -> set[str]:
        return get_email_addresses(package_info)

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        has_issues, message = super().detect(package_info, path, name, version)

        if has_issues:
            message += "\n\n" + NPM_API_MAINTAINER_EMAIL_WARNING

        return has_issues, message

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
        release_date = parser.isoparse(raw_date).replace(tzinfo=timezone.utc)
        return release_date
