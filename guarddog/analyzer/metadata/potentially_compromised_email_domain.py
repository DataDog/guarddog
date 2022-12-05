""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""

from datetime import datetime
from typing import Optional

import whois  # type: ignore
from dateutil import parser
from packaging import version

from guarddog.analyzer.metadata.detector import Detector


def _get_project_latest_release_date(ecosystem: str, package_info) -> Optional[datetime]:
    """
    Gets the most recent release date of a Python project

    Args:
        releases (dict): PyPI JSON API's representation field

    Returns:
        datetime: creation date of the most recent in releases
    """
    if ecosystem == "pypi":
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
    if ecosystem == 'npm':
        latest_release_version = package_info["dist-tags"]["latest"]
        raw_date = package_info["time"][latest_release_version]
        release_date = parser.isoparse(raw_date).replace(tzinfo=None)
        return release_date
    return None


def _get_domain_creation_date(email_domain) -> tuple[Optional[datetime], bool]:
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


def get_email_addresses(ecosystem: str, package_info: dict) -> list[str]:
    if ecosystem == 'pypi':
        author_email = package_info["info"]["author_email"]
        maintainer_email = package_info["info"]["maintainer_email"]
        email = author_email or maintainer_email
        return [email]

    if ecosystem == 'npm':
        return list(map(lambda x: x["email"], package_info["maintainers"]))

    raise NotImplementedError(f"not implemented for ecosystem {ecosystem}")


class PotentiallyCompromisedEmailDomainDetector(Detector):
    """
    Detector for compromised email domain attacks. Checks if the author's email domain was
    reregistered before the most recent package released
    """

    def detect(self, package_info, ecosystem: str) -> tuple[bool, str]:
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

        emails = get_email_addresses(ecosystem, package_info)

        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        latest_project_release = _get_project_latest_release_date(ecosystem, package_info)

        has_issues = False
        messages = []
        for email in emails:
            sanitized_email = email.strip().replace(">", "").replace("<", "")
            email_domain = sanitized_email.split("@")[-1]
            domain_creation_date, domain_exists = _get_domain_creation_date(email_domain)

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
