from guarddog.utils.npm import published_versions_before, resolve_npm_alias


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
