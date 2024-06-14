from abc import abstractmethod
from datetime import datetime
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

from .utils import extract_email_address_domain, get_domain_creation_date


class PotentiallyCompromisedEmailDomainDetector(Detector):
    # The name of the rule is dependent on the ecosystem and is provided by the implementing subclasses
    def __init__(self, ecosystem: str):
        super().__init__(
            name="potentially_compromised_email_domain",
            description="Identify when a package maintainer e-mail domain (and therefore package manager account) "
            "might have been compromised",
        )
        self.ecosystem = ecosystem

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Uses a package's information to determine
        if the maintainer's email domain might have been compromised

        Args:
            package_info (dict): package info from the package repository

        Returns:
            bool: True if email domain may be compromised
            str: Message explaining the issue
        """

        emails = self.get_email_addresses(package_info)

        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        latest_project_release = self.get_project_latest_release_date(package_info)

        has_issues = False
        messages = []
        for email in emails:
            domain = extract_email_address_domain(email)
            # note: get_domain_creation_date is cached
            domain_creation_date, domain_exists = get_domain_creation_date(domain)

            if not domain_exists:
                # will be caught by the "unclaimed_maintainer_email_domain" detector
                continue
            if domain_creation_date is None or latest_project_release is None:
                continue
            if latest_project_release < domain_creation_date:
                has_issues = True

                messages.append(
                    f"The domain name of the maintainer's email address ({email}) was"
                    " re-registered after"
                    " the latest release of this "
                    "package. This can be an indicator that this is a"
                    ""
                    " custom domain that expired, and was leveraged by"
                    " an attacker to compromise the"
                    f" package owner's {self.ecosystem}"
                    " account."
                )

        return has_issues, "\n".join(messages)

    @abstractmethod
    def get_project_latest_release_date(self, package_info) -> Optional[datetime]:
        pass

    @abstractmethod
    def get_email_addresses(self, package_info) -> set[str]:
        return set()
