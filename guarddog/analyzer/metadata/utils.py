from datetime import datetime
from typing import Optional

import whois  # type: ignore

NPM_MAINTAINER_EMAIL_WARNING = (
    "note that NPM's API may not provide accurate information regarding the maintainer's email, "
    "so this detector may cause false positives for NPM packages. "
    "see https://www.theregister.com/2022/05/10/security_npm_email/"
)


def get_email_domain_creation_date(email) -> tuple[Optional[datetime], bool]:
    """
    Gets the creation date of an email address domain

    Args:
        email (str): email address

    Raises:
        Exception: "Domain {email_domain} does not exist"
        ValueError: "Invalid email address: {email}"

    Returns:
        datetime: creation date of email_domain
        bool:     if the domain is currently registered
    """

    sanitized_email = email.strip().replace(">", "").replace("<", "")

    try:
        email_domain = sanitized_email.split("@")[-1]
    except IndexError:
        raise ValueError(f"Invalid email address: {email}")

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
