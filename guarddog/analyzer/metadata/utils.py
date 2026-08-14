import contextlib
import io
import logging
import threading
from datetime import datetime, timezone
from functools import cache
from typing import Optional

import hashlib
import whois  # type: ignore
from whois.exceptions import PywhoisError  # type: ignore[import-untyped]

_log = logging.getLogger("guarddog")

# Serializes sys.stdout redirection to prevent output loss when multiple
# threads call whois concurrently via ThreadPoolExecutor.
_stdout_redirect_lock = threading.Lock()


@contextlib.contextmanager
def _suppress_whois_stdout():
    """Suppress stdout during a whois call to hide non-fatal socket timeout messages.

    python-whois emits these via print() rather than Python logging, so they
    cannot be filtered by log level. Captured output is forwarded to the debug
    logger when DEBUG logging is enabled.
    """
    import sys

    captured = io.StringIO()
    with _stdout_redirect_lock:
        original_stdout = sys.stdout
        sys.stdout = captured
        try:
            yield
        finally:
            sys.stdout = original_stdout
            output = captured.getvalue()
            if output and _log.isEnabledFor(logging.DEBUG):
                _log.debug("[whois] %s", output.strip())


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
        with _suppress_whois_stdout():
            domain_information = whois.whois(domain)
    except PywhoisError as e:
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

    return creation_dates.replace(tzinfo=timezone.utc), True


def extract_email_address_domain(email_address: str):
    sanitized_email = email_address.strip().replace(">", "").replace("<", "")

    try:
        domain = sanitized_email.split("@")[-1]
        return domain

    except IndexError:
        raise ValueError(f"Invalid email address: {email_address}")


def get_file_hash(path: str) -> tuple[str, list[str]]:
    """
    Gets the sha256 of the file

    Args:
        path (str): Full file path

    Returns:
        str: The SHA256 hash of the file as a hexadecimal string
        list: The file contents as a list of lines
    """
    with open(path, "rb") as f:
        # Read the contents of the file
        file_contents = f.read()
        # Create a hash object
        hash_object = hashlib.sha256()
        # Feed the file contents to the hash object
        hash_object.update(file_contents)
        # Get the hexadecimal hash value
        return hash_object.hexdigest(), str(file_contents).strip().splitlines()
