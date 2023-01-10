import json
import os
import pathlib
from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.npm import NPMReleaseZeroDetector
from guarddog.analyzer.metadata.pypi import PypiReleaseZeroDetector
from tests.analyzer.metadata.resources.sample_project_info import (
    PACKAGE_INFO,
    generate_project_info,
)

with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "npm_data.json"), "r") as file:
    NPM_PACKAGE_INFO = json.load(file)

pypi_detector = PypiReleaseZeroDetector()
npm_detector = NPMReleaseZeroDetector()

class TestEmptyInformation:
    zero_release = generate_project_info("version", "0.0.0")
    npm_zero_release = deepcopy(NPM_PACKAGE_INFO)
    npm_zero_release["dist-tags"]["latest"] = "0.0.0"

    @pytest.mark.parametrize("info, detector", [(zero_release, pypi_detector), (npm_zero_release, npm_detector)])
    def test_zero(self, info, detector):
        matches, _ = detector.detect(info)
        assert matches

    @pytest.mark.parametrize("info, detector", [(PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_nonempty(self, info, detector):
        matches, _ = detector.detect(info)
        assert not matches
