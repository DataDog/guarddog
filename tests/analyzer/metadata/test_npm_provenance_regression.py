from guarddog.analyzer.metadata.npm.provenance_regression import (
    NPMProvenanceRegressionDetector,
)


ATTESTATIONS = {
    "url": "https://registry.npmjs.org/-/npm/v1/attestations/parent@1.0.0",
    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
}


def make_info(versions_attested, times, latest, name="parent"):
    """Build a minimal npm registry metadata dict.

    `versions_attested` maps version -> bool, where True means the version's
    `dist` carries provenance `attestations` and False means it does not.
    """
    versions = {}
    for v, attested in versions_attested.items():
        dist = {"tarball": f"https://registry.npmjs.org/{name}/-/{name}-{v}.tgz"}
        if attested:
            dist["attestations"] = ATTESTATIONS
        versions[v] = {"dist": dist}
    return {
        "name": name,
        "dist-tags": {"latest": latest},
        "versions": versions,
        "time": times,
    }


class TestProvenanceRegression:
    detector = NPMProvenanceRegressionDetector()

    def test_latest_with_attestations_not_flagged(self):
        info = make_info(
            versions_attested={"1.0.0": True, "1.1.0": True},
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
                "modified": "2020-06-01T00:00:00.000Z",
            },
            latest="1.1.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_regression_against_immediately_preceding_version(self):
        info = make_info(
            versions_attested={"1.0.0": True, "1.1.0": False},
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
                "modified": "2020-06-01T00:00:00.000Z",
            },
            latest="1.1.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is True
        assert message is not None
        assert "1.1.0" in message  # the current version
        assert "1.0.0" in message  # the last attested version

    def test_regression_several_versions_back(self):
        # 1.0.0 had attestations (N-4); 1.1.0, 1.2.0, 1.3.0 dropped them; 1.4.0
        # (latest) also lacks them. A naive N-vs-N-1 check would miss this because
        # the immediately preceding 1.3.0 has no attestations either.
        info = make_info(
            versions_attested={
                "1.0.0": True,
                "1.1.0": False,
                "1.2.0": False,
                "1.3.0": False,
                "1.4.0": False,
            },
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-02-01T00:00:00.000Z",
                "1.2.0": "2020-03-01T00:00:00.000Z",
                "1.3.0": "2020-04-01T00:00:00.000Z",
                "1.4.0": "2020-05-01T00:00:00.000Z",
                "modified": "2020-05-01T00:00:00.000Z",
            },
            latest="1.4.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is True
        assert message is not None
        assert "1.4.0" in message  # the current version
        assert "1.0.0" in message  # references the last attested version, N-4

    def test_never_had_attestations_not_flagged(self):
        info = make_info(
            versions_attested={"1.0.0": False, "1.1.0": False, "1.2.0": False},
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
                "1.2.0": "2020-12-01T00:00:00.000Z",
                "modified": "2020-12-01T00:00:00.000Z",
            },
            latest="1.2.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_single_version_no_prior_history(self):
        info = make_info(
            versions_attested={"1.0.0": False},
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
            },
            latest="1.0.0",
        )
        matched, message = self.detector.detect(info)
        assert matched is False
        assert message is None

    def test_explicit_version_argument_respected(self):
        # Scanning the earlier 1.1.0 (which itself dropped attestations after 1.0.0)
        # flags against 1.0.0 even though a later attested 1.2.0 exists.
        info = make_info(
            versions_attested={"1.0.0": True, "1.1.0": False, "1.2.0": True},
            times={
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2020-06-01T00:00:00.000Z",
                "1.2.0": "2020-12-01T00:00:00.000Z",
                "modified": "2020-12-01T00:00:00.000Z",
            },
            latest="1.2.0",
        )
        matched, message = self.detector.detect(info, version="1.1.0")
        assert matched is True
        assert message is not None
        assert "1.1.0" in message
        assert "1.0.0" in message
