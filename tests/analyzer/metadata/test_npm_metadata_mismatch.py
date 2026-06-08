from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.npm.npm_metadata_mismatch import (
    NPMMetadataMismatch,
    _normalize_git_url,
    diff_at_key_dict,
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

    def test_git_url_trailing_dot_git_no_false_positive(
        self, mocker, npm_package_info
    ):
        """Git URLs differing only by trailing .git should not trigger a mismatch.

        Regression test for https://github.com/DataDog/guarddog/issues/634
        """
        package_json_metadata = deepcopy(
            npm_package_info["versions"][self.target_version]
        )
        package_json_metadata["dependencies"] = {
            "libsignal": "git+https://github.com/whiskeysockets/libsignal-node"
        }
        npm_version_metadata = deepcopy(npm_package_info)
        npm_version_metadata["versions"][self.target_version]["dependencies"] = {
            "libsignal": "git+https://github.com/whiskeysockets/libsignal-node.git"
        }
        npm_version_metadata["dist-tags"]["latest"] = self.target_version

        mocker.patch("json.loads", lambda v: package_json_metadata)
        mocker.patch("pathlib.Path.read_text", lambda self: None)

        result, _ = self.mismatch_detector.detect(npm_version_metadata, path="./")
        assert result is False


class TestNormalizeGitUrl:
    """Unit tests for _normalize_git_url."""

    def test_strips_trailing_dot_git_from_git_plus_https(self):
        assert (
            _normalize_git_url("git+https://github.com/user/repo.git")
            == "git+https://github.com/user/repo"
        )

    def test_strips_trailing_dot_git_from_git_plus_ssh(self):
        assert (
            _normalize_git_url("git+ssh://github.com/user/repo.git")
            == "git+ssh://github.com/user/repo"
        )

    def test_strips_trailing_dot_git_from_bare_git_scheme(self):
        assert (
            _normalize_git_url("git://github.com/user/repo.git")
            == "git://github.com/user/repo"
        )

    def test_no_trailing_dot_git_unchanged(self):
        url = "git+https://github.com/user/repo"
        assert _normalize_git_url(url) == url

    def test_non_git_url_unchanged(self):
        assert _normalize_git_url("1.2.3") == "1.2.3"
        assert _normalize_git_url("^2.0.0") == "^2.0.0"
        assert _normalize_git_url("https://example.com/pkg.git") == "https://example.com/pkg.git"

    def test_none_passthrough(self):
        assert _normalize_git_url(None) is None

    def test_non_string_passthrough(self):
        assert _normalize_git_url(42) == 42


class TestDiffAtKeyDictGitUrls:
    """Ensure diff_at_key_dict uses git URL normalization."""

    def test_equivalent_git_urls_produce_no_diff(self):
        version = {"libsignal": "git+https://github.com/user/repo.git"}
        manifest = {"libsignal": "git+https://github.com/user/repo"}
        assert diff_at_key_dict(version, manifest) == []

    def test_genuinely_different_git_urls_still_detected(self):
        version = {"dep": "git+https://github.com/user/repo-a.git"}
        manifest = {"dep": "git+https://github.com/user/repo-b.git"}
        result = diff_at_key_dict(version, manifest)
        assert len(result) == 1
        assert result[0][0] == "dep"
