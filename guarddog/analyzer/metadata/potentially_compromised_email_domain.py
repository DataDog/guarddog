""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime

import whois
from dateutil import parser
from packaging import version

from guarddog.analyzer.metadata.detector import Detector


class PotentiallyCompromisedEmailDomainDetector(Detector):
    """
    Detector for compromised email dommain attacks. Checks if the author's email domain was
    reregistered before the most recent package released

    Args:
        Detector (_type_): _description_
    """

    def __init__(self) -> None:
        super(Detector)

    def _get_domain_creation_date(self, email_domain) -> tuple[datetime, bool]:
        """
        Gets the creation date of an email address domain

        Args:
            email_domain (str): domain of email address

        Raises:
            Exception: "Domain {email_domain} does not exist"

        Returns:
            datetime: creation date of email_domain
            bool:     if the domain is currently registered
        """

        try:
            domain_information = whois.whois(email_domain)
        except whois.parser.PywhoisError as e:
            # The domain doesn't exist at all, if that's the case we consider it vulnerable
            # since someone could register it
            return None, (not str(e).lower().startswith('no match for'))

        if domain_information.creation_date is None:
            # No creation date in whois, so we can't know
            return None, True

        creation_dates = domain_information.creation_date

        if type(creation_dates) is list:
            return min(creation_dates), True

        return creation_dates, True

    def _get_project_latest_release_date(self, releases) -> datetime:
        """
        Gets the most recent release date of a Python project

        Args:
            releases (dict): PyPI JSON API's representation field

        Returns:
            datetime: creation date of the most recent in releases
        """

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

    def detect(self, package_info) -> bool:
        """
        Uses a package's information from PyPI's JSON API to determine
        if the package's email domain might have been compromised

        Args:
            package_info (dict): dictionary representation of PyPI's JSON
                output

        Raises:
            Exception: "Email for {package_info['info']['name']} does not exist."

        Returns:
            bool: True if email domain is compromised
        """

        author_email = package_info["info"]["author_email"]
        maintainer_email = package_info["info"]["maintainer_email"]
        email = author_email or maintainer_email

        releases = package_info["releases"]

        if email is None or len(email) == 0:
            # No e-mail is set for this package, hence no risk
            return False

        sanitized_email = email.strip().replace(">", "").replace("<", "")
        email_domain = sanitized_email.split("@")[-1]

        latest_project_release = self._get_project_latest_release_date(releases)
        domain_creation_date, domain_exists = self._get_domain_creation_date(email_domain)
        if not domain_exists:
            return True
        if domain_creation_date is None:
            return False
        return latest_project_release < domain_creation_date
