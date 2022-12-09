""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime
from typing import Optional
from dateutil import parser
from packaging import version

from guarddog.analyzer.metadata.potentially_compromised_email_domain import PotentiallyCompromisedEmailDomainDetector


def _get_project_latest_release_date(package_info) -> Optional[datetime]:
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


def get_email_addresses(package_info: dict) -> list[str]:
    author_email = package_info["info"]["author_email"]
    maintainer_email = package_info["info"]["maintainer_email"]
    email = author_email or maintainer_email
    return [email]


class PypiPotentiallyCompromisedEmailDomainDetector(PotentiallyCompromisedEmailDomainDetector):
    """
    Detector for compromised email domain attacks. Checks if the author's email domain was
    reregistered before the most recent package released
    """

    RULE_NAME = "potentially_compromised_email_domain"

    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, str]:
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

        emails = get_email_addresses(package_info)

        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        latest_project_release = _get_project_latest_release_date(package_info)

        has_issues = False
        messages = []
        for email in emails:
            sanitized_email = email.strip().replace(">", "").replace("<", "")
            email_domain = sanitized_email.split("@")[-1]
            domain_creation_date, domain_exists = self._get_domain_creation_date(email_domain)

            if not domain_exists:
                has_issues = True
                messages.append(f"The maintainer's email ({email}) domain does not exist and can likely be registered "
                                f"by an attacker to compromise the maintainer's PyPi account")
            if domain_creation_date is None or latest_project_release is None:
                continue
            if latest_project_release < domain_creation_date:
                has_issues = True
                messages.append(f"The domain name of the maintainer's email address ({email}) was"" re-registered after"
                                " the latest release of this ""package. This can be an indicator that this is a"""
                                " custom domain that expired, and was leveraged by"" an attacker to compromise the"
                                " package owner's PyPi"" account.")
        return has_issues, "\n".join(messages)
