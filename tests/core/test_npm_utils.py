from guarddog.utils.npm import (
    parse_semver,
    precedes_in_release_order,
    published_versions_before,
    resolve_npm_alias,
)


class TestParseSemver:
    def test_valid_semver(self):
        assert str(parse_semver("1.2.3")) == "1.2.3"

    def test_invalid_semver_is_none(self):
        assert parse_semver("not-semver") is None


class TestPrecedesInReleaseOrder:
    def test_earlier_version_precedes(self):
        assert precedes_in_release_order("1.0.0", "1.1.0") is True

    def test_semver_greater_version_does_not_precede(self):
        assert precedes_in_release_order("8.0.0-alpha.1", "7.8.2") is False

    def test_prerelease_of_current_line_counts_by_default(self):
        assert precedes_in_release_order("2.0.0-beta.1", "2.0.0") is True

    def test_prerelease_excluded_for_stable_when_policy_off(self):
        assert (
            precedes_in_release_order(
                "2.0.0-beta.1", "2.0.0", prereleases_inform_stable=False
            )
            is False
        )

    def test_prerelease_informs_prerelease_under_either_policy(self):
        assert (
            precedes_in_release_order(
                "2.0.0-alpha.1", "2.0.0-beta.1", prereleases_inform_stable=False
            )
            is True
        )

    def test_invalid_semver_falls_back_to_publish_order(self):
        assert precedes_in_release_order("not-semver", "1.0.0") is True


class TestPublishedVersionsBefore:
    package_info = {
        "versions": {"1.0.0": {}, "1.1.0": {}, "1.2.0": {}},
        "time": {
            "created": "2024-01-01T00:00:00.000Z",
            "1.0.0": "2024-01-01T00:00:00.000Z",
            "1.1.0": "2024-02-01T00:00:00.000Z",
            "1.2.0": "2024-03-01T00:00:00.000Z",
            "modified": "2024-03-01T00:00:00.000Z",
        },
    }

    def test_returns_earlier_versions_most_recent_first(self):
        assert published_versions_before(self.package_info, "1.2.0") == [
            "1.1.0",
            "1.0.0",
        ]

    def test_oldest_version_has_no_history(self):
        assert published_versions_before(self.package_info, "1.0.0") == []

    def test_unknown_version_has_no_history(self):
        assert published_versions_before(self.package_info, "9.9.9") == []

    def test_unpublished_versions_are_excluded(self):
        info = {
            "versions": {"1.0.0": {}, "1.2.0": {}},
            "time": dict(self.package_info["time"]),
        }
        assert published_versions_before(info, "1.2.0") == ["1.0.0"]

    def test_version_without_publish_timestamp_has_no_history(self):
        info = {
            "versions": dict(self.package_info["versions"]),
            "time": {
                k: v for k, v in self.package_info["time"].items() if k != "1.2.0"
            },
        }
        assert published_versions_before(info, "1.2.0") == []

    def test_missing_time_map(self):
        assert published_versions_before({"versions": {"1.0.0": {}}}, "1.0.0") == []


class TestResolveNpmAlias:
    def test_alias_resolves_to_real_package(self):
        assert resolve_npm_alias("alias", "npm:react@19.2.3") == ("react", "19.2.3")

    def test_scoped_alias_without_selector(self):
        assert resolve_npm_alias("alias", "npm:@scope/pkg") == ("@scope/pkg", "*")

    def test_plain_selector_unchanged(self):
        assert resolve_npm_alias("react", "^19.0.0") == ("react", "^19.0.0")
