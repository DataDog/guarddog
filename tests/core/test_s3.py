import os
import unittest
import unittest.mock as mock

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from guarddog.utils import s3


class TestS3Helpers(unittest.TestCase):
    def test_is_s3_url(self):
        assert s3.is_s3_url("s3://bucket/key")
        assert not s3.is_s3_url("https://example.com/x")
        assert not s3.is_s3_url("/local/path")

    def test_parse_s3_uri(self):
        assert s3.parse_s3_uri("s3://bucket/path/to/pkg") == (
            "bucket",
            "path/to/pkg",
        )
        assert s3.parse_s3_uri("s3://bucket/prefix/") == ("bucket", "prefix/")

    def test_parse_s3_uri_missing_bucket(self):
        with pytest.raises(ValueError):
            s3.parse_s3_uri("s3:///key-without-bucket")

    def test_safe_join_rejects_traversal(self):
        with pytest.raises(ValueError):
            s3._safe_join("/tmp/dest", "../../etc/passwd")

    def test_safe_join_allows_nested(self):
        result = s3._safe_join("/tmp/dest", "a/b/c.js")
        assert result == os.path.realpath("/tmp/dest/a/b/c.js")


class TestVerifyAuth(unittest.TestCase):
    def test_missing_credentials_raises(self):
        client = mock.MagicMock()
        client.get_caller_identity.side_effect = NoCredentialsError()
        with mock.patch("boto3.client", return_value=client):
            with pytest.raises(RuntimeError):
                s3.verify_aws_authentication()

    def test_success(self):
        client = mock.MagicMock()
        with mock.patch("boto3.client", return_value=client):
            s3.verify_aws_authentication()
        client.get_caller_identity.assert_called_once()


def _not_found_error():
    return ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject"
    )


class TestDownloadFromS3(unittest.TestCase):
    def test_single_archive_object(self):
        client = mock.MagicMock()
        client.head_object.return_value = {}
        with mock.patch("boto3.client", return_value=client):
            with mock.patch("os.makedirs"):
                kind, path = s3.download_from_s3(
                    "s3://bucket/path/pkg.tgz", "/tmp/dest"
                )
        assert kind == "archive"
        assert path.endswith("pkg.tgz")
        client.download_file.assert_called_once()

    def test_single_non_archive_object_is_folder(self):
        client = mock.MagicMock()
        client.head_object.return_value = {}
        with mock.patch("boto3.client", return_value=client):
            with mock.patch("os.makedirs"):
                kind, path = s3.download_from_s3(
                    "s3://bucket/path/index.js", "/tmp/dest"
                )
        assert kind == "folder"
        assert path == "/tmp/dest"

    def test_prefix_downloads_each_object(self):
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found_error()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "path/pkg/"},  # directory marker, skipped
                    {"Key": "path/pkg/package.json"},
                    {"Key": "path/pkg/lib/index.js"},
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        with mock.patch("boto3.client", return_value=client):
            with mock.patch("os.makedirs"):
                kind, path = s3.download_from_s3(
                    "s3://bucket/path/pkg", "/tmp/dest"
                )
        assert kind == "folder"
        assert path == "/tmp/dest"
        assert client.download_file.call_count == 2
        downloaded_keys = {c.args[1] for c in client.download_file.call_args_list}
        assert downloaded_keys == {
            "path/pkg/package.json",
            "path/pkg/lib/index.js",
        }

    def test_empty_prefix_raises(self):
        client = mock.MagicMock()
        client.head_object.side_effect = _not_found_error()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{}]
        client.get_paginator.return_value = paginator
        with mock.patch("boto3.client", return_value=client):
            with pytest.raises(RuntimeError):
                s3.download_from_s3("s3://bucket/missing", "/tmp/dest")
