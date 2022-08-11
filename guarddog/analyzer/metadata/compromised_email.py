""" Compromised Email Detector

Detects if a maintainer's email domain has been compromised.
"""

from datetime import datetime

import whois
from dateutil import parser
from dotenv import load_dotenv
from packaging import version

from guarddog.analyzer.metadata.detector import Detector


class CompromisedEmailDetector(Detector):
    def __init__(self) -> None:
        load_dotenv()

        super(Detector)

    def _get_domain_creation_date(self, email_domain) -> datetime:
        domain_information = whois.whois(email_domain)

        if domain_information.creation_date is None:
            raise Exception(f"Domain {email_domain} does not exist")

        creation_dates = domain_information.creation_date

        if type(creation_dates) is list:
            return min(creation_dates)

        return creation_dates

    def _get_project_creation_date(self, releases) -> datetime:
        sorted_versions = sorted(releases.keys(), key=lambda r: version.parse(r), reverse=True)
        earlier_versions = sorted_versions[:-1]

        for early_version in earlier_versions:
            version_release = releases[early_version]

            if len(version_release) > 0:  # if there's a distribution for the package
                upload_time_text = version_release[0]["upload_time_iso_8601"]
                creation_date = parser.isoparse(upload_time_text).replace(tzinfo=None)
                return creation_date

    def is_email_compromised(self, package_info) -> bool:
        author_email = package_info["info"]["author_email"]
        maintainer_email = package_info["info"]["maintainer_email"]
        email = author_email or maintainer_email

        releases = package_info["releases"]

        if email is None or len(email) == 0:
            raise Exception(f"Email for {package_info['info']['name']} does not exist.")

        sanitized_email = email.strip().replace(">", "").replace("<", "")
        email_domain = sanitized_email.split("@")[-1]

        project_date = self._get_project_creation_date(releases)
        domain_date = self._get_domain_creation_date(email_domain)
        return project_date < domain_date

    def detect(self, package_info) -> bool:
        return self.is_email_compromised(package_info)
