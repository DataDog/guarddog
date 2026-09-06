"""Tests for the whois stdout suppression fix (see guarddog/analyzer/metadata/utils.py)."""

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pytest
from _pytest.monkeypatch import MonkeyPatch

import guarddog.analyzer.metadata.utils as utils_mod
from guarddog.analyzer.metadata.utils import _suppress_stdout, get_domain_creation_date
from tests.analyzer.metadata.utils import MockWhoIs


@pytest.fixture(autouse=True)
def clear_cache():
    utils_mod.get_domain_creation_date.cache_clear()


def test_noisy_whois_does_not_pollute_stdout(capsys):
    """Socket timeout messages printed by python-whois must not appear on stdout."""
    def noisy_whois(domain):
        print("Error trying to connect to socket: closing socket - timed out")
        return MockWhoIs(datetime(1990, 1, 31))

    utils_mod._log.setLevel(logging.INFO)
    MonkeyPatch().setattr("whois.whois", noisy_whois)

    get_domain_creation_date("example.com")

    assert capsys.readouterr().out == ""


def test_suppression_does_not_affect_return_value():
    """Suppressing stdout must not change the domain creation date returned."""
    expected = datetime(1990, 1, 31)

    def noisy_whois(domain):
        print("Error trying to connect to socket: closing socket - timed out")
        return MockWhoIs(expected)

    MonkeyPatch().setattr("whois.whois", noisy_whois)
    creation_date, domain_exists = get_domain_creation_date("example.com")

    assert domain_exists is True
    assert creation_date is not None
    assert creation_date.date() == expected.date()


def test_concurrent_calls_do_not_corrupt_stdout():
    """Concurrent whois calls must not leave sys.stdout pointing at an internal buffer."""
    real_stdout = sys.stdout
    errors = []

    def worker(thread_id):
        with _suppress_stdout():
            print(f"noisy-whois-thread-{thread_id}")
        if sys.stdout is not real_stdout:
            errors.append(f"thread {thread_id}: sys.stdout corrupted")

    with ThreadPoolExecutor(max_workers=10) as pool:
        for fut in as_completed([pool.submit(worker, i) for i in range(10)]):
            fut.result()

    assert errors == [], "\n".join(errors)


def test_suppression_returns_captured_stdout():
    """Callers can decide what to do with suppressed stdout."""
    with _suppress_stdout() as stdout:
        print("captured output")

    assert stdout.getvalue() == "captured output\n"
