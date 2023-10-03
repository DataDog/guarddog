from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.npm.direct_url_dependency import (
    NPMDirectURLDependencyDetector,
)
from tests.analyzer.metadata.resources.sample_project_info import NPM_PACKAGE_INFO


class TestDirectURLDependency:
    npm_detector = NPMDirectURLDependencyDetector()

    test_data = [
        ("2.0.1", False),
        ("http://asdf.com/asdf.tar.gz", True),
        ("git+ssh://git@github.com:npm/cli.git#v1.0.27", True),
        ("git+ssh://git@github.com:npm/cli#semver:^5.0", True),
        ("git+https://isaacs@github.com/npm/cli.git", True),
        ("git://github.com/npm/cli.git#v1.0.27", True),
        ("expressjs/express", True),
        ("mochajs/mocha#4727d357ea", True),
        ("user/repo#feature\/branch", True),
    ]

    @pytest.mark.parametrize("version,expected_matches", test_data)
    def test_npm_direct_url_dependencies(self, version, expected_matches):
        package_info = deepcopy(NPM_PACKAGE_INFO)
        package_info["versions"]["2.0.0"]["dependencies"]["foo"] = version
        matches, _ = self.npm_detector.detect(
            package_info, name="", path="", version="2.0.0"
        )
        assert matches == expected_matches
