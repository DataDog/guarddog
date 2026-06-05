import os.path
import tempfile

import pytest

from guarddog.scanners import GithubActionScanner


def test_get_git_tarball_url_for_tag():
    scanner = GithubActionScanner()
    url = scanner._get_git_tarball_url("actions/checkout", "v4.2.2")
    assert url == "https://github.com/actions/checkout/archive/v4.2.2.zip"


def test_get_git_tarball_url_for_commit_sha():
    # A commit-sha pinned action (the case from issue #714). The old
    # tag-only URL "https://github.com/<repo>/archive/refs/tags/<sha>.zip"
    # 404s for a SHA, so the generic /archive/<ref>.zip endpoint must be used.
    scanner = GithubActionScanner()
    sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
    url = scanner._get_git_tarball_url("actions/checkout", sha)
    assert url == f"https://github.com/actions/checkout/archive/{sha}.zip"
    assert "refs/tags" not in url


def test_get_git_tarball_url_for_branch():
    scanner = GithubActionScanner()
    url = scanner._get_git_tarball_url("actions/checkout", "main")
    assert url == "https://github.com/actions/checkout/archive/main.zip"
    assert "refs/tags" not in url


def test_get_git_tarball_url_without_version():
    scanner = GithubActionScanner()
    url = scanner._get_git_tarball_url("actions/checkout")
    assert url == "https://api.github.com/repos/actions/checkout/zipball"


def test_download_and_get_github_action_by_url():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(
            tmpdirname, "https://github.com/actions/checkout.git", "v4.2.2"
        )
        assert not data
        assert os.path.exists(
            os.path.join(
                tmpdirname,
                "https:--github.com-actions-checkout.git",
                "checkout-4.2.2",
                "package.json",
            )
        )


def test_download_and_get_github_action_by_name():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(
            tmpdirname, "actions/checkout", "v4.2.2"
        )
        assert not data
        assert os.path.exists(
            os.path.join(
                tmpdirname, "actions-checkout", "checkout-4.2.2", "package.json"
            )
        )
