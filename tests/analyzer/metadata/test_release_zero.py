import pytest

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector
from tests.analyzer.metadata.resources.sample_project_info import (
    PACKAGE_INFO,
    generate_project_info,
)


class TestEmptyInformation:
    detector = ReleaseZeroDetector()
    nonzero_release = PACKAGE_INFO
    zero_release = generate_project_info("version", "0.0.0")

    @pytest.mark.parametrize("package_info", [zero_release])
    def test_zero(self, package_info):
        matches, _ = self.detector.detect(package_info)
        assert matches

    @pytest.mark.parametrize("package_info", [nonzero_release])
    def test_nonempty(self, package_info):
        matches, _ = self.detector.detect(package_info)
        assert not matches
