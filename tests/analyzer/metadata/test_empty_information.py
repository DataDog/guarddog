import os
import tempfile

import pytest

from guarddog.analyzer.metadata.npm import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.pypi import PypiEmptyInfoDetector
from tests.analyzer.metadata.resources.sample_project_info import (
    PACKAGE_INFO,
    generate_project_info,
)


class TestEmptyInformation:
    pypi_detector = PypiEmptyInfoDetector()
    npm_detector = NPMEmptyInfoDetector()
    nonempty_information = PACKAGE_INFO
    empty_information = generate_project_info("description", "")

    @pytest.mark.parametrize("package_info", [empty_information])
    def test_empty(self, package_info):
        matches, _ = self.pypi_detector.detect(package_info)
        assert matches

    @pytest.mark.parametrize("package_info", [nonempty_information])
    def test_nonempty(self, package_info):
        matches, _ = self.pypi_detector.detect(package_info)
        assert not matches

    def test_empty_npm(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            matches, _ = self.npm_detector.detect({}, dir)
            assert matches

    def test_non_empty_npm(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "README.md"), "w") as readme:
                readme.write("# Hello World")
            matches, _ = self.npm_detector.detect({}, dir)
            assert not matches

    def test_non_empty_npm_with_mixed_case(self):
        with tempfile.TemporaryDirectory() as dir:
            full_path = os.path.join(dir, "package")
            os.mkdir(full_path)
            with open(os.path.join(full_path, "Readme.md"), "w") as readme:
                readme.write("# Hello World")
            matches, _ = self.npm_detector.detect({}, dir)
            assert not matches
