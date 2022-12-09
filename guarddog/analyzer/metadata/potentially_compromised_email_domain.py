""" Compromised Email Detector

Detects if a maintainer's email domain might have been compromised.
"""
from datetime import datetime
from typing import Optional

import whois  # type: ignore

from guarddog.analyzer.metadata.detector import Detector


class PotentiallyCompromisedEmailDomainDetector(Detector):
    RULE_NAME = "potentially_compromised_email_domain"

    def _get_domain_creation_date(self, email_domain) -> tuple[Optional[datetime], bool]:
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
