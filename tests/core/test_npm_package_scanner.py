import os.path
import tempfile

import pytest

from guarddog.scanners import NPMPackageScanner


def test_download_and_get_package_info():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "minivlad")
        assert path
        assert path.endswith("/minivlad")
        assert os.path.exists(os.path.join(tmpdirname, "minivlad", "package", "package.json"))
        assert "1.0.0" in data["versions"]


def test_download_and_get_package_info_npm_namespaced():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "@datadog/browser-logs")
        assert path
        assert path.endswith("/@datadog-browser-logs")
        assert os.path.exists(os.path.join(tmpdirname, "@datadog-browser-logs"))


@pytest.mark.parametrize("identifier", ["expressjs/express", "https://github.com/expressjs/express.git"])
@pytest.mark.skip("Git targets are not yet supported for npm")
def test_download_and_get_package_info_from_github(identifier):
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "identifier")
        assert os.path.exists(os.path.join(tmpdirname, "express", "package", "package.json"))
        assert "1.0.0" in data["versions"]


def test_download_and_get_package_info_non_existing_packages():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        try:
            scanner.download_and_get_package_info(tmpdirname, "@datadog/minivlad")
        except Exception as e:
            assert e
