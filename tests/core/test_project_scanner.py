from unittest import mock

import pytest

from guarddog.scanners.pypi_project_scanner import PypiRequirementsScanner
from guarddog.scanners.scanner import (
    _build_raw_github_url,
    github_blob_to_raw_url,
)


def test_build_raw_github_url_valid():
    assert (
        _build_raw_github_url(
            "https://github.com/owner/repo", "main", "requirements.txt"
        )
        == "https://raw.githubusercontent.com/owner/repo/main/requirements.txt"
    )


def test_build_raw_github_url_strips_dot_git():
    assert (
        _build_raw_github_url(
            "https://github.com/owner/repo.git", "main", "requirements.txt"
        )
        == "https://raw.githubusercontent.com/owner/repo/main/requirements.txt"
    )


def test_build_raw_github_url_accepts_www_host():
    assert (
        _build_raw_github_url(
            "https://www.github.com/owner/repo", "main", "requirements.txt"
        )
        == "https://raw.githubusercontent.com/owner/repo/main/requirements.txt"
    )


def test_build_raw_github_url_upgrades_http_to_https():
    assert (
        _build_raw_github_url(
            "http://github.com/owner/repo", "main", "requirements.txt"
        )
        == "https://raw.githubusercontent.com/owner/repo/main/requirements.txt"
    )


def test_build_raw_github_url_quotes_branch_and_filename():
    # `?` and `#` would otherwise truncate the path; `/` in branch is preserved.
    assert _build_raw_github_url(
        "https://github.com/owner/repo", "feature/foo?bar", "sub dir/req.txt"
    ) == (
        "https://raw.githubusercontent.com/owner/repo"
        "/feature/foo%3Fbar/sub%20dir/req.txt"
    )


# Regression test for GHSA-587r-mc96-6f2p: a userinfo-bearing URL like
# `http://github@127.0.0.1:18081/owner/repo` previously routed to 127.0.0.1
# and leaked the GH_TOKEN via HTTP Basic auth.
def test_build_raw_github_url_rejects_userinfo():
    with pytest.raises(ValueError, match="userinfo"):
        _build_raw_github_url(
            "http://github@127.0.0.1:18081/owner/repo",
            "main",
            "requirements.txt",
        )


def test_build_raw_github_url_rejects_non_github_host():
    with pytest.raises(ValueError, match="host"):
        _build_raw_github_url("https://evil.com/owner/repo", "main", "requirements.txt")


def test_build_raw_github_url_rejects_lookalike_host():
    with pytest.raises(ValueError, match="host"):
        _build_raw_github_url(
            "https://github.com.evil.com/owner/repo",
            "main",
            "requirements.txt",
        )


def test_build_raw_github_url_rejects_explicit_port():
    with pytest.raises(ValueError, match="port"):
        _build_raw_github_url(
            "https://github.com:8443/owner/repo",
            "main",
            "requirements.txt",
        )


def test_build_raw_github_url_rejects_bad_path():
    with pytest.raises(ValueError, match="owner/repo"):
        _build_raw_github_url(
            "https://github.com/justowner", "main", "requirements.txt"
        )
    with pytest.raises(ValueError, match="owner/repo"):
        _build_raw_github_url(
            "https://github.com/owner/repo/extra",
            "main",
            "requirements.txt",
        )


def test_build_raw_github_url_rejects_bad_scheme():
    with pytest.raises(ValueError, match="scheme"):
        _build_raw_github_url("file:///etc/passwd", "main", "requirements.txt")
    with pytest.raises(ValueError, match="scheme"):
        _build_raw_github_url("ftp://github.com/owner/repo", "main", "requirements.txt")


# End-to-end regression: a malicious URL must be rejected before any HTTP
# request is made and before GitHub credentials are read from the environment.
def test_scan_remote_rejects_malicious_url():
    scanner = PypiRequirementsScanner()
    with (
        mock.patch("guarddog.scanners.scanner.requests.get") as mock_get,
        mock.patch.object(scanner, "_authenticate_by_access_token") as mock_auth,
    ):
        with pytest.raises(ValueError):
            scanner.scan_remote(
                "http://github@127.0.0.1:18081/owner/repo",
                "main",
                "requirements.txt",
            )
        mock_get.assert_not_called()
        mock_auth.assert_not_called()


def test_github_blob_to_raw_url_converts_blob_link():
    assert (
        github_blob_to_raw_url("https://github.com/owner/repo/blob/main/dir/file.zip")
        == "https://raw.githubusercontent.com/owner/repo/main/dir/file.zip"
    )


def test_github_blob_to_raw_url_accepts_www_host():
    # The naive string replace this replaced produced www.raw.githubusercontent.com.
    assert (
        github_blob_to_raw_url("https://www.github.com/owner/repo/blob/main/file.zip")
        == "https://raw.githubusercontent.com/owner/repo/main/file.zip"
    )


def test_github_blob_to_raw_url_preserves_branch_with_slashes_and_query():
    assert (
        github_blob_to_raw_url(
            "https://github.com/owner/repo/blob/refs/heads/main/file.zip?token=1"
        )
        == "https://raw.githubusercontent.com/owner/repo/refs/heads/main/file.zip?token=1"
    )


def test_github_blob_to_raw_url_passes_through_non_github_url():
    url = "https://example.com/path/file.zip"
    assert github_blob_to_raw_url(url) == url


def test_github_blob_to_raw_url_passes_through_non_blob_github_url():
    url = "https://github.com/owner/repo/raw/main/file.zip"
    assert github_blob_to_raw_url(url) == url


# Same credential-leak class as _build_raw_github_url: a recognizably GitHub URL
# carrying userinfo or an explicit port must be rejected, not silently converted.
def test_github_blob_to_raw_url_rejects_userinfo():
    with pytest.raises(ValueError, match="userinfo"):
        github_blob_to_raw_url(
            "https://user:pass@github.com/owner/repo/blob/main/file.zip"
        )


def test_github_blob_to_raw_url_rejects_explicit_port():
    with pytest.raises(ValueError, match="port"):
        github_blob_to_raw_url("https://github.com:8443/owner/repo/blob/main/file.zip")
