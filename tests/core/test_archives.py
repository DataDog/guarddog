import binascii
import os
import struct
import zipfile

import pytest

from guarddog.utils.archives import safe_extract

FIXTURES = os.path.join(os.path.dirname(__file__), "resources", "archives")
ENCRYPTED_ZIP = os.path.join(FIXTURES, "encrypted.zip")
PLAIN_TARGZ = os.path.join(FIXTURES, "plain.tar.gz")
ZIP_PASSWORD = b"hunter2"


def _build_zip(
    members: dict[str, bytes],
    cd_size: int | None = None,
    data_descriptor: bool = False,
) -> bytes:
    """
    Build a stored (uncompressed) ZIP by hand so the End-Of-Central-Directory
    size-of-central-directory field can be overridden. With ``cd_size=0`` the
    archive reproduces the parser-differential from issue #780: zipfile reads it
    as empty while the local file headers still carry every member.

    When ``data_descriptor`` is set, each local file header sets general-purpose
    bit 3 and zeroes its inline sizes/crc, deferring them to a trailing data
    descriptor (PK\\x07\\x08). The local-header walk cannot follow past such an
    entry, which exercises the "count before bailing out" path of the guard.
    """
    body = bytearray()
    central = bytearray()
    offsets = []
    for name, data in members.items():
        raw = name.encode()
        crc = binascii.crc32(data) & 0xFFFFFFFF
        offsets.append(len(body))
        if data_descriptor:
            body += b"PK\x03\x04" + struct.pack(
                "<HHHHHIIIHH", 20, 0x08, 0, 0, 0x21, 0, 0, 0, len(raw), 0
            )
            body += raw + data
            body += b"PK\x07\x08" + struct.pack("<III", crc, len(data), len(data))
            continue
        body += b"PK\x03\x04" + struct.pack(
            "<HHHHHIIIHH", 20, 0, 0, 0, 0x21, crc, len(data), len(data), len(raw), 0
        )
        body += raw + data
    real_cd_size = 0
    for (name, data), offset in zip(members.items(), offsets):
        raw = name.encode()
        crc = binascii.crc32(data) & 0xFFFFFFFF
        record = (
            b"PK\x01\x02"
            + struct.pack(
                "<HHHHHHIIIHHHHHII",
                20,
                20,
                0,
                0,
                0,
                0x21,
                crc,
                len(data),
                len(data),
                len(raw),
                0,
                0,
                0,
                0,
                (0o100644) << 16,
                offset,
            )
            + raw
        )
        central += record
        real_cd_size += len(record)
    count = len(members)
    eocd_cd_size = real_cd_size if cd_size is None else cd_size
    eocd = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, count, count, eocd_cd_size, len(body), 0
    )
    return bytes(body) + bytes(central) + eocd


_WHL_MEMBERS = {
    "pkg/__init__.py": b"print('hello')\n",
    "pkg-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n",
}


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


def test_well_formed_zip_extracts(tmp_path):
    archive = tmp_path / "pkg-1.0-py3-none-any.whl"
    archive.write_bytes(_build_zip(_WHL_MEMBERS))
    out = tmp_path / "out"
    out.mkdir()
    safe_extract(str(archive), str(out))
    assert (out / "pkg" / "__init__.py").read_bytes() == _WHL_MEMBERS["pkg/__init__.py"]


def test_cd_size_zero_eocd_differential_rejected(tmp_path):
    # zipfile reads this as empty (namelist() == []) but the payload is still
    # present in the local file headers; safe_extract must refuse it (issue #780).
    archive = tmp_path / "crafted-1.0-py3-none-any.whl"
    archive.write_bytes(_build_zip(_WHL_MEMBERS, cd_size=0))

    with zipfile.ZipFile(str(archive)) as zf:
        assert zf.namelist() == []

    with pytest.raises(ValueError, match="parser anomaly"):
        safe_extract(str(archive), str(tmp_path / "out"))


def test_cd_size_zero_with_data_descriptor_rejected(tmp_path):
    # Same EOCD differential as above, but the first local header uses a data
    # descriptor (general-purpose bit 3, sizes deferred to a trailing record).
    # The walk cannot follow past such an entry, yet it must still count it so the
    # "empty central directory but non-empty payload" anomaly is rejected (#780).
    archive = tmp_path / "crafted-dd-1.0-py3-none-any.whl"
    archive.write_bytes(_build_zip(_WHL_MEMBERS, cd_size=0, data_descriptor=True))

    with zipfile.ZipFile(str(archive)) as zf:
        assert zf.namelist() == []

    with pytest.raises(ValueError, match="parser anomaly"):
        safe_extract(str(archive), str(tmp_path / "out"))
