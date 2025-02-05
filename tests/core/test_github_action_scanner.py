import os.path
import tempfile

import pytest

from guarddog.scanners import GithubActionScanner


def test_download_and_get_github_action_by_url():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "https://github.com/expressjs/express.git", "v5.0.0")
        assert not data
        assert os.path.exists(os.path.join(tmpdirname, "https:--github.com-expressjs-express.git", "express-5.0.0", "package.json"))


def test_download_and_get_github_action_by_name():
    scanner = GithubActionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "expressjs/express", "v5.0.0")
        assert not data
        assert os.path.exists(os.path.join(tmpdirname, "expressjs-express", "express-5.0.0", "package.json"))
