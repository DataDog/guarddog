from abc import abstractmethod
from typing import Optional
import os

from disposable_email_domains import blocklist
from guarddog.analyzer.metadata.detector import Detector

from .utils import extract_email_address_domain


class DeceptiveAuthorDetector(Detector):
    """This heuristic detects when an author is using a disposable email."""

    MESSAGE_TEMPLATE = "An author was detected using a disposable email %s"

    def __init__(self):
        super().__init__(
            name="deceptive_author",
            description="This heuristic detects when an author is using a disposable email",
        )

    def get_email_addresses(self, package_info: dict) -> set[str]:
        return set()

    @staticmethod
    def get_suspicious_email_domains() -> set:
        """
        Gets the domains that are known to be used by suspicious authors.
        """
        # Obtain the path to the file containing knonw placeholder email domains
        placeholder_email_domains_filename = "placeholder_email_domains.txt"

        resources_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "resources")
        )

        disposable_email_domains_path = os.path.join(
            resources_dir, placeholder_email_domains_filename
        )

        placeholder_email_domains_data = None
        with open(disposable_email_domains_path, "r") as placeholder_email_domains_file:
            placeholder_email_domains_data = set(
                placeholder_email_domains_file.read().split("\n")
            )

        return blocklist | placeholder_email_domains_data

    def _get_normalized_domain(self, domain: str) -> str:
        """
        Returns a normalized version of the domain address.
        The format should be ready to compare against the list of known disposable domains.
        """
        domain = domain.lower().strip()
        return ".".join(domain.split(".")[-2:]) 

    @abstractmethod
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        emails = self.get_email_addresses(package_info)

        if len(emails) == 0:
            # No e-mail is set for this package, hence no risk
            return False, "No e-mail found for this package"

        for email in emails:
            domain = self._get_normalized_domain(extract_email_address_domain(email))

            if domain in DeceptiveAuthorDetector.get_suspicious_email_domains():
                return True, self.MESSAGE_TEMPLATE % email
        return False, ""
