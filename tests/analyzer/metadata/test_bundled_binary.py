import os
import tempfile

import pytest

from guarddog.analyzer.metadata.bundled_binary import BundledBinary
from guarddog.analyzer.metadata.npm import NPMBundledBinary
from guarddog.analyzer.metadata.pypi import PypiBundledBinary
from tests.analyzer.metadata.resources.sample_project_info import (
    PYPI_PACKAGE_INFO, generate_pypi_project_info)

pypi_detector = PypiBundledBinary()
npm_detector = NPMBundledBinary()


class TestBundleBinary:
    nonempty_information = PYPI_PACKAGE_INFO
    binary_sample_exe = b"\x4D\x5A" + b"0x90" * 10  # exe magic number plus nop sled
    binary_sample_elf = (
        b"\x7F\x45\x4C\x46" + b"0x90" * 10
    )  # elf magic number plus nop sled

    @pytest.mark.parametrize(
        "detector",
        [
            (pypi_detector),
            (npm_detector),
        ],
    )
    def test_exe(self, detector: BundledBinary):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "windows.txt"), "wb") as f:
                f.write(self.binary_sample_exe)
            matches, _ = detector.detect({}, dir)
            assert matches

    @pytest.mark.parametrize(
        "detector",
        [
            (pypi_detector),
            (npm_detector),
        ],
    )
    def test_elf(self, detector: BundledBinary):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "linux.txt"), "wb") as f:
                f.write(self.binary_sample_elf)
            matches, _ = detector.detect({}, dir)
            assert matches

    @pytest.mark.parametrize(
        "detector",
        [
            (pypi_detector),
            (npm_detector),
        ],
    )
    def test_plain(self, detector: BundledBinary):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "file.exe"), "w") as f:
                f.write("Hello world")
            matches, _ = detector.detect({}, dir)
            assert not matches

    @pytest.mark.parametrize(
        "detector",
        [
            (pypi_detector),
            (npm_detector),
        ],
    )
    def test_empty(self, detector: BundledBinary):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "some_file"), "w") as f:
                pass
            matches, _ = detector.detect({}, dir)
            assert not matches

    @pytest.mark.parametrize(
        "detector",
        [
            (pypi_detector),
            (npm_detector),
        ],
    )
    def test_multiplebinaries(self, detector: BundledBinary):
        with tempfile.TemporaryDirectory() as dir:
            full_path1 = os.path.join(dir, "package")
            os.mkdir(full_path1)
            with open(os.path.join(full_path1, "file1"), "wb") as f:
                f.write(self.binary_sample_elf)
            full_path2 = os.path.join(full_path1, "nested")
            os.mkdir(full_path2)
            with open(os.path.join(full_path2, "file2"), "wb") as f:
                f.write(self.binary_sample_exe)

            matches, msg = detector.detect({}, dir)

            assert matches
            assert "file1" in msg
            assert "exe" in msg
            assert "file2" in msg
            assert "elf" in msg
