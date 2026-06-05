import os

import pytest

from guarddog.utils.archives import safe_extract

FIXTURES = os.path.join(os.path.dirname(__file__), "resources", "archives")
ENCRYPTED_ZIP = os.path.join(FIXTURES, "encrypted.zip")
PLAIN_TARGZ = os.path.join(FIXTURES, "plain.tar.gz")
ZIP_PASSWORD = b"hunter2"


def test_encrypted_zip_extracts_with_correct_password(tmp_path):
    safe_extract(ENCRYPTED_ZIP, str(tmp_path), zip_password=ZIP_PASSWORD)
    assert (tmp_path / "index.js").read_text() == 'console.log("hi")\n'
    assert (tmp_path / "package.json").read_text().startswith("{")


def test_encrypted_zip_missing_password_raises(tmp_path):
    with pytest.raises(RuntimeError, match="password required"):
        safe_extract(ENCRYPTED_ZIP, str(tmp_path))


def test_encrypted_zip_wrong_password_raises(tmp_path):
    with pytest.raises(RuntimeError, match="[Bb]ad password"):
        safe_extract(ENCRYPTED_ZIP, str(tmp_path), zip_password=b"nope")


def test_tar_archive_rejects_password(tmp_path):
    with pytest.raises(ValueError, match="only supported for ZIP"):
        safe_extract(PLAIN_TARGZ, str(tmp_path), zip_password=ZIP_PASSWORD)
