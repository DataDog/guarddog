from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

from .utils import extract_email_address_domain, get_domain_creation_date


class UnclaimedMaintainerEmailDomainDetector(Detector):
    # The name of the rule is dependent on the ecosystem and is provided by the implementing subclasses
    def __init__(self, ecosystem: str):
        description = (
            "Identify when a package maintainer e-mail domain (and therefore package manager account) "
            "is currently unclaimed and could be registered by an attacker"
        )

        super().__init__(
            name="unclaimed_maintainer_email_domain",
            description=description,
        )
        self.ecosystem = ecosystem

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
        Uses a package's information to determine
        if the maintainer's email domain is unclaimed and thus exposed to hijacking

        Args:
            package_info (dict): package info from the package repository

        Returns:
            bool: True if email domain is unclaimed
            str: Message explaining the issue
        """

        emails = self.get_email_addresses(package_info)

        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        has_issues = False
        messages = []
        for email in emails:
            domain = extract_email_address_domain(email)
            # note: get_domain_creation_date is cached
            _, domain_exists = get_domain_creation_date(domain)

            if domain_exists:
                continue

            # domain does not exist

            has_issues = True

            messages.append(
                f"The maintainer's email ({email}) domain does not exist and can likely be registered "
                f"by an attacker to compromise the maintainer's {self.ecosystem} account"
            )

        return has_issues, "\n".join(messages)

    @abstractmethod
    def get_project_latest_release_date(self, package_info):
        pass

    @abstractmethod
    def get_email_addresses(self, package_info) -> set[str]:
        return set()
