from copy import deepcopy

from guarddog.analyzer.metadata.npm.npm_shrinkwrap_file import (
    NPMShrinkwrapFile,
)

from tests.analyzer.metadata.resources.package_fixtures import npm_package_info

class TestNPMShrinkwrapFile:
    detector = NPMShrinkwrapFile()

    def test_npm_shrinkwrap_check(self, mocker):
        mocker.patch("pathlib.Path.is_file", lambda self: True)
        result, desc = self.detector.detect(deepcopy(npm_package_info), path="./")
        assert result
