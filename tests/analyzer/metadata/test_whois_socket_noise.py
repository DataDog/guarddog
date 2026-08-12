"""
Tests for the whois stdout suppression fix.

The python-whois library emits socket timeout messages directly via print(),
bypassing Python's logging system.  These messages have no functional impact
on scan results but confuse users.

This test file verifies that:
1. _suppress_whois_stdout hides print() output in normal (non-debug) mode.
2. get_domain_creation_date still returns correct results after suppression.
3. The captured text is forwarded to the debug logger when DEBUG is active.
4. Concurrent calls from multiple threads cannot corrupt sys.stdout (thread-safety).
"""

import io
import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from unittest.mock import patch

import pytest
from _pytest.monkeypatch import MonkeyPatch

import guarddog.analyzer.metadata.utils as utils_mod
from guarddog.analyzer.metadata.utils import _suppress_whois_stdout, get_domain_creation_date
from tests.analyzer.metadata.utils import MockWhoIs


# ------------------------------------------------------------------ fixtures


@pytest.fixture(autouse=True)
def clear_cache():
    """Each test gets a fresh cache so mocked whois values are honoured."""
    utils_mod.get_domain_creation_date.cache_clear()


# ------------------------------------------------------------------ tests


class TestSuppressWhoisStdout:
    """Unit-level tests for the _suppress_whois_stdout context manager."""

    def test_print_output_is_hidden_in_normal_mode(self):
        """
        Any text printed inside the context manager must not reach the real
        stdout when the guarddog logger is NOT at DEBUG level.
        """
        real_stdout = io.StringIO()
        # Patch sys.stdout so we can observe what reaches the 'real' terminal.
        with patch.object(sys, "stdout", real_stdout):
            # Simulate normal (INFO) log level - not DEBUG.
            utils_mod._log.setLevel(logging.INFO)

            # Enter the context manager; it will swap sys.stdout again.
            with _suppress_whois_stdout():
                print("Error trying to connect to socket: closing socket - timed out")

        # Nothing should have leaked to the outer (real) stdout.
        assert real_stdout.getvalue() == ""

    def test_print_output_forwarded_to_debug_logger(self, caplog):
        """
        When the logger is at DEBUG level, the captured text must appear in
        the debug log rather than being silently dropped.
        """
        utils_mod._log.setLevel(logging.DEBUG)

        with caplog.at_level(logging.DEBUG, logger="guarddog"):
            with _suppress_whois_stdout():
                print("Error trying to connect to socket: closing socket - timed out")

        assert any(
            "closing socket" in record.message
            for record in caplog.records
            if record.levelno == logging.DEBUG
        ), "Expected the whois socket error to appear in the debug log"

        utils_mod._log.setLevel(logging.INFO)

    def test_suppression_does_not_affect_return_values(self):
        """
        The context manager must not interfere with values returned from
        code executed inside the block.
        """
        result = None
        with _suppress_whois_stdout():
            result = 42

        assert result == 42

    def test_stdout_is_restored_after_context_exits(self):
        """
        sys.stdout must be the same object before and after the context
        manager, even if an exception is raised inside.
        """
        original = sys.stdout

        try:
            with _suppress_whois_stdout():
                raise RuntimeError("intentional error inside context")
        except RuntimeError:
            pass

        assert sys.stdout is original


class TestSuppressWhoisStdoutThreadSafety:
    """
    Regression tests for the thread-safety fix applied to _suppress_whois_stdout.

    Without _stdout_redirect_lock the following race is possible when GuardDog
    scans packages in parallel with ThreadPoolExecutor:

        Thread A: original = sys.stdout      # real terminal
        Thread A: sys.stdout = bufA
        Thread B: original = sys.stdout      # snapshots bufA, NOT the terminal
        Thread B: sys.stdout = bufB
        Thread A: sys.stdout = original_A    # terminal restored - OK
        Thread B: sys.stdout = original_B    # restores to bufA - terminal LOST

    From this point forward everything Thread B writes disappears silently into
    bufA.  The lock ensures only one thread holds the redirection at a time.
    """

    def test_concurrent_calls_do_not_corrupt_stdout(self):
        """
        10 threads simultaneously using _suppress_whois_stdout must all finish
        with sys.stdout pointing at the original terminal, not at any thread's
        internal StringIO buffer.

        Before the lock was added this test would fail intermittently because
        the interleaved swap/restore would leave sys.stdout as one of the
        internal capture buffers.
        """
        real_stdout = sys.stdout
        errors = []

        def worker(thread_id):
            with _suppress_whois_stdout():
                print(
                    "Error trying to connect to socket: "
                    f"closing socket - timed out (thread {thread_id})"
                )
            # After the context exits, sys.stdout must be the real terminal.
            if sys.stdout is not real_stdout:
                errors.append(
                    f"Thread {thread_id}: sys.stdout is {sys.stdout!r}, "
                    f"expected {real_stdout!r}"
                )

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(worker, i) for i in range(10)]
            for fut in as_completed(futures):
                fut.result()  # propagate any unexpected exception

        assert errors == [], (
            "sys.stdout was corrupted in concurrent calls:\n" + "\n".join(errors)
        )
        # Final sanity check: the main thread's stdout is still intact.
        assert sys.stdout is real_stdout

    def test_output_not_lost_under_concurrency(self):
        """
        Each thread's noisy whois print() must remain isolated inside its own
        capture buffer and must NOT leak to the real stdout.

        We use a threading.Barrier so all 5 threads enter the context manager
        at the same time, maximising the race window that the lock must close.
        """
        real_out = io.StringIO()
        original_stdout = sys.stdout
        # Redirect the real stdout so we can measure any leaks.
        sys.stdout = real_out

        try:
            barrier = threading.Barrier(5)

            def worker(thread_id):
                # All threads enter together to maximise the race window.
                barrier.wait()
                with _suppress_whois_stdout():
                    print(f"noisy-whois-output-thread-{thread_id}")

            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = [pool.submit(worker, i) for i in range(5)]
                for fut in as_completed(futures):
                    fut.result()
        finally:
            sys.stdout = original_stdout

        leaked = real_out.getvalue()
        assert leaked == "", (
            f"Whois noise leaked to real stdout under concurrency: {leaked!r}"
        )


class TestGetDomainCreationDateSuppression:
    """
    Integration-level tests that exercise get_domain_creation_date with a
    mocked whois that simulates the noisy print() calls the real library makes.
    """

    def test_noisy_whois_does_not_pollute_stdout(self, capsys):
        """
        Even when the mocked whois prints a socket error, nothing must appear
        on stdout in normal (INFO) mode.
        """
        def noisy_whois(domain):
            print("Error trying to connect to socket: closing socket - timed out")
            return MockWhoIs(datetime(1990, 1, 31))

        utils_mod._log.setLevel(logging.INFO)
        MonkeyPatch().setattr("whois.whois", noisy_whois)

        get_domain_creation_date("example.com")

        captured = capsys.readouterr()
        assert captured.out == "", (
            "Socket noise from whois must not appear on stdout in normal mode"
        )

    def test_noisy_whois_result_is_correct(self):
        """
        Suppressing stdout must not change the returned domain creation date.
        """
        expected_date = datetime(1990, 1, 31)

        def noisy_whois(domain):
            print("Error trying to connect to socket: closing socket - timed out")
            return MockWhoIs(expected_date)

        MonkeyPatch().setattr("whois.whois", noisy_whois)

        creation_date, domain_exists = get_domain_creation_date("example.com")

        assert domain_exists is True
        assert creation_date is not None
        assert creation_date.year == expected_date.year
        assert creation_date.month == expected_date.month
        assert creation_date.day == expected_date.day
