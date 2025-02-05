import os.path
import tempfile

import pytest

from guarddog.scanners import GithubActionScanner


def test_download_and_get_github_action_by_url():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "https://github.com/actions/checkout.git", "v4.2.2")
        assert not data
        assert os.path.exists(os.path.join(tmpdirname, "https:--github.com-actions-checkout.git", "checkout-4.2.2", "package.json"))


def test_download_and_get_github_action_by_name():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "actions/checkout", "v4.2.2")
        assert not data
        assert os.path.exists(os.path.join(tmpdirname, "actions-checkout", "checkout-4.2.2", "package.json"))
