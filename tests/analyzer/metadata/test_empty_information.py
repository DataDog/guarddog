import pytest

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector
from tests.analyzer.metadata.resources.sample_project_info import (
    PACKAGE_INFO,
    generate_project_info,
)


class TestEmptyInformation:
    detector = EmptyInfoDetector()
    nonempty_information = PACKAGE_INFO
    empty_information = generate_project_info("description", "")

    @pytest.mark.parametrize("package_info", [empty_information])
    def test_empty(self, package_info):
        matches, _ = self.detector.detect(package_info)
        assert matches

    @pytest.mark.parametrize("package_info", [nonempty_information])
    def test_nonempty(self, package_info):
        matches, _ = self.detector.detect(package_info)
        assert not matches
