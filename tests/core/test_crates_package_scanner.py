import os
from io import BytesIO
from unittest.mock import Mock, patch

import pytest

from guarddog.scanners import CratesPackageScanner

CRATE_INFO = {
    "crate": {
        "name": "serde",
        "max_stable_version": "1.0.228",
    },
    "versions": [
        {
            "num": "1.0.228",
            "dl_path": "/api/v1/crates/serde/1.0.228/download",
        },
        {
            "num": "1.0.227",
            "dl_path": "/api/v1/crates/serde/1.0.227/download",
        },
    ],
}


@patch("guarddog.scanners.crates_package_scanner.requests.get")
def test_download_and_get_latest_crate(mock_get, tmp_path):
    response = Mock()
    response.json.return_value = CRATE_INFO
    mock_get.return_value = response

    scanner = CratesPackageScanner()
    scanner.download_compressed = Mock()

    data, path = scanner.download_and_get_package_info(str(tmp_path), "serde")

    response.raise_for_status.assert_called_once()
    mock_get.assert_called_once_with(
        "https://crates.io/api/v1/crates/serde",
        headers=scanner.request_headers,
    )
    assert data == CRATE_INFO
    assert path == os.path.join(str(tmp_path), "serde-1.0.228")
    scanner.download_compressed.assert_called_once_with(
        "https://crates.io/api/v1/crates/serde/1.0.228/download",
        os.path.join(str(tmp_path), "serde-1.0.228.crate"),
        path,
    )


@patch("guarddog.scanners.crates_package_scanner.requests.get")
def test_download_and_get_requested_crate_version(mock_get, tmp_path):
    response = Mock()
    response.json.return_value = CRATE_INFO
    mock_get.return_value = response

    scanner = CratesPackageScanner()
    scanner.download_compressed = Mock()

    _, path = scanner.download_and_get_package_info(str(tmp_path), "serde", "1.0.227")

    assert path == os.path.join(str(tmp_path), "serde-1.0.227")
    scanner.download_compressed.assert_called_once_with(
        "https://crates.io/api/v1/crates/serde/1.0.227/download",
        os.path.join(str(tmp_path), "serde-1.0.227.crate"),
        path,
    )


@patch("guarddog.scanners.crates_package_scanner.requests.get")
def test_download_rejects_unknown_crate_version(mock_get, tmp_path):
    response = Mock()
    response.json.return_value = CRATE_INFO
    mock_get.return_value = response

    scanner = CratesPackageScanner()

    with pytest.raises(ValueError, match="Version 9.9.9 for crate serde not found"):
        scanner.download_and_get_package_info(str(tmp_path), "serde", "9.9.9")


@patch("guarddog.scanners.crates_package_scanner.requests.get")
def test_download_encodes_path_separators_in_crate_name_and_version(mock_get, tmp_path):
    package_info = {
        "crate": {"name": "../serde", "max_stable_version": "../1.0.0"},
        "versions": [
            {
                "num": "../1.0.0",
                "dl_path": "/api/v1/crates/serde/1.0.0/download",
            }
        ],
    }
    response = Mock()
    response.json.return_value = package_info
    mock_get.return_value = response

    scanner = CratesPackageScanner()
    scanner.download_compressed = Mock()

    _, path = scanner.download_and_get_package_info(
        str(tmp_path), "../serde", "../1.0.0"
    )

    expected_stem = "..%2Fserde-..%2F1.0.0"
    assert path == os.path.join(str(tmp_path), expected_stem)
    scanner.download_compressed.assert_called_once_with(
        "https://crates.io/api/v1/crates/serde/1.0.0/download",
        os.path.join(str(tmp_path), f"{expected_stem}.crate"),
        path,
    )


def test_get_package_version_uses_resolved_latest_version():
    scanner = CratesPackageScanner()

    assert scanner.get_package_version(CRATE_INFO) == "1.0.228"
    assert scanner.get_package_version(CRATE_INFO, "1.0.227") == "1.0.227"


@patch("guarddog.scanners.crates_package_scanner.requests.get")
def test_fetch_archive_uses_crates_io_user_agent(mock_get, tmp_path):
    response = Mock()
    response.raw = BytesIO(b"crate archive")
    mock_get.return_value = response
    archive_path = tmp_path / "serde.crate"
    scanner = CratesPackageScanner()

    scanner._fetch_archive("https://crates.io/download", str(archive_path))

    mock_get.assert_called_once_with(
        "https://crates.io/download",
        headers=scanner.request_headers,
        stream=True,
    )
    response.raise_for_status.assert_called_once()
    assert archive_path.read_bytes() == b"crate archive"
