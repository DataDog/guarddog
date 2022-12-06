from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector
from tests.analyzer.metadata.resources.sample_npm_project_info import NPM_PACKAGE_INFO
from tests.analyzer.metadata.resources.sample_project_info import (
    PACKAGE_INFO,
    generate_project_info,
)


class TestEmptyInformation:
    detector = ReleaseZeroDetector()
    zero_release = generate_project_info("version", "0.0.0")
    npm_zero_release = deepcopy(NPM_PACKAGE_INFO)
    npm_zero_release["dist-tags"]["latest"] = "0.0.0"

    @pytest.mark.parametrize("inputs", [(zero_release, "pypi"), (npm_zero_release, "npm")])
    def test_zero(self, inputs):
        info, ecosystem = inputs
        matches, _ = self.detector.detect(info, ecosystem)
        assert matches

    @pytest.mark.parametrize("inputs", [(PACKAGE_INFO, "pypi"), (NPM_PACKAGE_INFO, "npm")])
    def test_nonempty(self, inputs):
        info, ecosystem = inputs
        matches, _ = self.detector.detect(info, ecosystem)
        assert not matches

    def test_non_existing_ecosystem(self):
        try:
            self.detector.detect({}, "foo")
        except NotImplementedError as e:
            assert e
