import os
import tempfile

import pytest

from guarddog.analyzer.metadata.npm import NPMBundledBinary
from guarddog.analyzer.metadata.pypi import PypiBundledBinary
from tests.analyzer.metadata.resources.sample_project_info import (
    PYPI_PACKAGE_INFO,
    generate_pypi_project_info,
)


class TestBundleBinary:
    pypi_detector = PypiBundledBinary()
    npm_detector = NPMBundledBinary()
    nonempty_information = PYPI_PACKAGE_INFO
    

    def test_exe_npm(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "windows.txt"), "wb") as f:
                f.write(b"\x4D\x5A" + b"0x90"*10) # exe plus nop sled
            matches, _ = self.npm_detector.detect({}, dir)
            assert matches

    def test_elf_pypi(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "linux.txt"), "wb") as f:
                f.write(b"\x7F\x45\x4C\x46" + b"0x90"*10)
            matches, _ = self.pypi_detector.detect({}, dir)
            assert matches

    def test_plain(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "file.exe"), "w") as f:
                f.write("Hello world")
            matches, _ = self.npm_detector.detect({}, dir)
            assert not matches

    def test_empty(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "some_file"), "w") as f:
                pass
            matches, _ = self.pypi_detector.detect({}, dir)
            assert not matches