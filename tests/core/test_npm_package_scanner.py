import os.path
import tempfile

import pytest

from guarddog.analyzer.metadata.npm.metadata_mismatch import (
    NPMMetadataMismatchDetector,
)
from guarddog.scanners import NPMPackageScanner


def test_download_and_get_package_info():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "minivlad")
        assert path
        assert path.endswith("/minivlad")
        assert os.path.exists(
            os.path.join(tmpdirname, "minivlad", "package", "package.json")
        )
        assert "1.0.0" in data["versions"]


def test_download_and_get_package_info_npm_namespaced():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(
            tmpdirname, "@datadog/browser-logs"
        )
        assert path
        assert path.endswith("/@datadog-browser-logs")
        assert os.path.exists(os.path.join(tmpdirname, "@datadog-browser-logs"))


def test_metadata_mismatch_on_scoped_npm_package():
    """Regression test for https://github.com/DataDog/guarddog/issues/847."""
    scanner = NPMPackageScanner()
    detector = NPMMetadataMismatchDetector()

    with tempfile.TemporaryDirectory() as tmpdirname:
        package_info, path = scanner.download_and_get_package_info(
            tmpdirname, "@types/node", version="26.2.0"
        )

        result, description = detector.detect(
            package_info,
            path=path,
            name="@types/node",
            version="26.2.0",
        )

        assert result is False
        assert description == "No differences found"


@pytest.mark.parametrize(
    "identifier", ["expressjs/express", "https://github.com/expressjs/express.git"]
)
@pytest.mark.skip("Git targets are not yet supported for npm")
def test_download_and_get_package_info_from_github(identifier):
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(tmpdirname, "identifier")
        assert os.path.exists(
            os.path.join(tmpdirname, "express", "package", "package.json")
        )
        assert "1.0.0" in data["versions"]


def test_download_and_get_package_info_non_existing_packages():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        try:
            scanner.download_and_get_package_info(tmpdirname, "@datadog/minivlad")
        except Exception as e:
            assert e
