from datetime import datetime, timezone
from functools import cache
from typing import Optional

import whois  # type: ignore


NPM_MAINTAINER_EMAIL_WARNING = (
    "note that NPM's API may not provide accurate information regarding the maintainer's email, "
    "so this detector may cause false positives for NPM packages. "
    "see https://www.theregister.com/2022/05/10/security_npm_email/"
)


@cache
def get_domain_creation_date(domain) -> tuple[Optional[datetime], bool]:
    """
    Gets the creation date of an domain name

    Args:
        domain (str): domain of email address

    Returns:
        datetime: creation date of domain
        bool:     if the domain is currently registered
    """

    try:
        domain_information = whois.whois(domain)
    except whois.parser.PywhoisError as e:
        # The domain doesn't exist at all, if that's the case we consider it vulnerable
        # since someone could register it
        return None, (not str(e).lower().startswith("no match for"))

    if domain_information.creation_date is None:
        # No creation date in whois, so we can't know
        return None, True

    creation_dates = domain_information.creation_date

    if type(creation_dates) is list:
        # TZ info is updated to turn all dates into TZ aware so we can compare them 
        return min([d.replace(tzinfo=timezone.utc) for d in creation_dates]), True

    return creation_dates, True


def extract_email_address_domain(email_address: str):
    sanitized_email = email_address.strip().replace(">", "").replace("<", "")

    try:
        domain = sanitized_email.split("@")[-1]
        return domain

    except IndexError:
        raise ValueError(f"Invalid email address: {email_address}")
