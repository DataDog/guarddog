from abc import abstractmethod
from typing import Optional
import os
from datetime import datetime, timedelta

import requests

from guarddog.analyzer.metadata.detector import Detector

from .utils import extract_email_address_domain

DISPOSABLE_EMAIL_DOMAINS_CACHE_LOCATION = os.environ.get(
    "GUARDDOG_DISPOSABLE_EMAIL_DOMAINS_CACHE_LOCATION"
)


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
    def get_disposable_email_domains() -> set:
        """
        Gets the domains that are known to provide disposable e-mails

        """
        disposable_email_domains_data = None  # contains the raw content of the disposable email domains file

        disposable_email_domains_url = \
            "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"

        # Obtain the path to the file containing the disposable email domains by config
        disposable_email_domains_filename = "disposable_email_domains.txt"
        resources_dir = DISPOSABLE_EMAIL_DOMAINS_CACHE_LOCATION
        if resources_dir is None:
            resources_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "resources")
            )

        disposable_email_domains_path = os.path.join(
            resources_dir, disposable_email_domains_filename
        )

        # Read data if file exists and is not older than 30 days
        if disposable_email_domains_filename in os.listdir(resources_dir):
            update_time = datetime.fromtimestamp(
                os.path.getmtime(disposable_email_domains_path)
            )

            if datetime.now() - update_time <= timedelta(days=30):
                with open(
                    disposable_email_domains_path, "r"
                ) as disposable_email_domains_file:
                    disposable_email_domains_data = disposable_email_domains_file.read()

        # If no valid data is present, fetch the data from the URL
        if disposable_email_domains_data is None:
            response = requests.get(disposable_email_domains_url).text
            with open(disposable_email_domains_path, "w+") as f:
                f.write(response)

            disposable_email_domains_data = response

        return set(disposable_email_domains_data.split("\n"))

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
            domain = extract_email_address_domain(email)

            if domain in DeceptiveAuthorDetector.get_disposable_email_domains():
                return True, self.MESSAGE_TEMPLATE % email
        return False, ""


if __name__ == "__main__":
    # If package is run as a script, update disposable email domains file
    DeceptiveAuthorDetector.get_disposable_email_domains()
