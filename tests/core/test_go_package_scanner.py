import pytest
import tempfile
import os

from guarddog.scanners import GoModuleScanner
from guarddog.scanners.go_package_scanner import escape_module_name


def test_download_and_get_package_info_with_version():
    scanner = GoModuleScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        test_module = "github.com/DataDog/zstd"
        test_version = "v1.5.5"

        data, path = scanner.download_and_get_package_info(
            tmpdirname, test_module, test_version
        )

        assert path
        assert path.endswith("/github.com-DataDog-zstd")
        assert test_version in data["Version"]


def test_download_and_get_package_info_without_version():
    scanner = GoModuleScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        test_module = "github.com/DataDog/zstd"

        data, path = scanner.download_and_get_package_info(tmpdirname, test_module)

        assert path
        assert path.endswith("/github.com-DataDog-zstd")
        assert data["Version"] != ""


@pytest.mark.parametrize(
    "module", ["go.uber.org/zap", "github.com/AlecAivazis/survey/v2"]
)
def test_escape_module_name(module):
    assert escape_module_name(module).islower()
