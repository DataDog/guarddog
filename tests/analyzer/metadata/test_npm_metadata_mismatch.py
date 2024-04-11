from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.npm.npm_metadata_mismatch import (
    NPMMetadataMismatch,
)
from tests.analyzer.metadata.resources.package_fixtures import (
    pypi_package_info,
    npm_package_info,
)


def modified_version_info(mod_keying, mod_value, info):
    if mod_keying is None or mod_value is None:
        return info
    target = info
    for key in mod_keying[:-1]:
        if key not in target:
            target[key] = dict()
        target = target[key]
    target[mod_keying[-1]] = mod_value
    return info


def modified_npm_metadata_at_version(mod_keying, mod_value, info, version):
    target_version = info["versions"][version]
    target_version = modified_version_info(mod_keying, mod_value, target_version)
    info["versions"][version] = target_version
    return info


class TestNPMMetadataMismatch:
    mismatch_detector = NPMMetadataMismatch()

    target_version = "2.1.0"
    test_data = [
        # Tuples of the form (["key", "subkey", "toedit"], "value to set manifest", "value to set package.json", expected result)
        # if a value to set is none the key will not be changed
        (None, None, None, False),
        (
            ["scripts", "preinstall"],
            "this-is-the-same.sh",
            "this-is-the-same.sh",
            False,
        ),
        (["scripts", "preinstall"], None, "this-is-not-the-same.sh", True),
        (["scripts", "preinstall"], "this-is-not-the-same.sh", None, True),
        (
            ["scripts", "preinstall"],
            "this-is-not-the-same.sh",
            "another-script.js",
            True,
        ),
        (["dependencies", "does.not.exit"], None, "1.0.1", True),
        (["dependencies", "does.not.exit"], "1.1.0", "1.0.1", True),
        (["main"], "index.js", "index.ts", True),
        (["main"], "index.js", "index.js", False),
        # Other fields are ignored to decrease false positives numbers.
        (["repository", "url"], "a", "b", False),
    ]

    @pytest.mark.parametrize("modification", test_data)
    def test_npm_metadata_check(self, mocker, npm_package_info, modification):
        package_json_metadata = deepcopy(
            npm_package_info["versions"][self.target_version]
        )
        package_json_metadata = modified_version_info(
            modification[0], modification[1], package_json_metadata
        )
        npm_version_metadata = deepcopy(npm_package_info)
        npm_version_metadata = modified_npm_metadata_at_version(
            modification[0], modification[2], npm_version_metadata, self.target_version
        )
        npm_version_metadata["dist-tags"]["latest"] = self.target_version

        mocker.patch("json.loads", lambda v: package_json_metadata)
        mocker.patch("pathlib.Path.read_text", lambda self: None)

        result, _ = self.mismatch_detector.detect(npm_version_metadata, path="./")
        assert result == modification[3]
        result, _ = self.mismatch_detector.detect(
            npm_version_metadata, path="./", version="2.1.0"
        )
        assert result == modification[3]
