import os.path
import tempfile
import json

import pytest

from guarddog.scanners import ExtensionScanner


def test_download_and_get_package_info():
    scanner = ExtensionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(
            tmpdirname, "wayou.vscode-todo-highlight"
        )
        assert path
        assert path.endswith("/wayou.vscode-todo-highlight")

        assert os.path.exists(path)

        package_json_found = False
        for root, dirs, files in os.walk(path):
            if "package.json" in files:
                package_json_found = True
                break
        assert (
            package_json_found
        ), "package.json should exist in the extracted extension"

        # data now contains raw marketplace API response
        assert "results" in data
        assert len(data["results"]) > 0
        assert "extensions" in data["results"][0]
        assert len(data["results"][0]["extensions"]) > 0

        extension = data["results"][0]["extensions"][0]
        assert "extensionName" in extension
        assert "publisher" in extension


def test_download_and_get_package_info_with_version():
    scanner = ExtensionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data, path = scanner.download_and_get_package_info(
            tmpdirname, "gerane.Theme-FlatlandMonokai", "0.0.6"
        )
        assert path
        assert path.endswith("/gerane.Theme-FlatlandMonokai")

        # data now contains raw marketplace API response
        assert "results" in data
        assert len(data["results"]) > 0
        extension = data["results"][0]["extensions"][0]
        assert "versions" in extension
        assert len(extension["versions"]) > 0
        # Note: We're using a relatively stable extension that hasn't been updated in a long while


def test_download_and_get_package_info_non_existing_package():
    scanner = ExtensionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        with pytest.raises(Exception) as exc_info:
            scanner.download_and_get_package_info(
                tmpdirname, "non-existent-publisher.non-existent-extension"
            )
        assert "not found" in str(exc_info.value).lower()


def test_download_and_get_package_info_non_existing_version():
    scanner = ExtensionScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        with pytest.raises(Exception) as exc_info:
            scanner.download_and_get_package_info(
                tmpdirname, "wayou.vscode-todo-highlight", "999.999.999"
            )
        assert "version" in str(exc_info.value).lower()


def test_scan_local_extension_directory():
    scanner = ExtensionScanner()

    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create a mock extension directory structure
        extension_dir = os.path.join(tmpdirname, "test-extension")
        os.makedirs(extension_dir)

        package_json = {
            "name": "test-extension",
            "displayName": "Test Extension",
            "description": "A test extension for GuardDog",
            "version": "1.0.0",
            "publisher": "test-publisher",
            "categories": ["Other"],
            "activationEvents": ["*"],
            "contributes": {
                "commands": [{"command": "test.hello", "title": "Hello World"}]
            },
        }

        package_json_path = os.path.join(extension_dir, "package.json")
        with open(package_json_path, "w") as f:
            json.dump(package_json, f)

        result = scanner.scan_local(extension_dir)

        assert "issues" in result
        assert "results" in result
