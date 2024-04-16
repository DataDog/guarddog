import json
import os
import pathlib
from copy import deepcopy
from datetime import datetime

import pytest
from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.npm import NPMPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.pypi import PypiPotentiallyCompromisedEmailDomainDetector
from tests.analyzer.metadata.resources.sample_project_info import (
    PYPI_PACKAGE_INFO,
    generate_pypi_project_info,
    generate_npm_project_info
    )

with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "npm_data.json"), "r") as file:
    NPM_PACKAGE_INFO = json.load(file)


class MockWhoIs:
    def __init__(self, date) -> None:
        self.creation_date = date


pypi_detector = PypiPotentiallyCompromisedEmailDomainDetector()
npm_detector = NPMPotentiallyCompromisedEmailDomainDetector()


class TestCompromisedEmail:

    @pytest.mark.parametrize("package_info, detector",
                             [(PYPI_PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_compromised(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert compromised

    @pytest.mark.parametrize("package_info, detector",
                             [(PYPI_PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_safe(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert not compromised

    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            import whois
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = pypi_detector.detect(PYPI_PACKAGE_INFO)
        assert not compromised

    empty_author_pypi = generate_pypi_project_info("author_email", None)
    empty_author_npm = generate_npm_project_info("maintainters", [{
        "name": "john doe",
        "email": None
    }])


    @pytest.mark.parametrize("package_info, detector",
                             [(empty_author_pypi, pypi_detector), (empty_author_npm, npm_detector)])
    def test_email_domain_none(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert not compromised

    def test_single_package_version(self):
        """
        Regression test for https://github.com/DataDog/guarddog/issues/190
        """
        current_info = deepcopy(PYPI_PACKAGE_INFO)

        current_info["releases"] = {"1.0": [{
            "upload_time": "2023-03-06T00:41:25",
            "upload_time_iso_8601": "2023-03-06T00:41:25.953817Z"
        }]}
        try:
            pypi_detector.detect(current_info)
            pass  # we expect no exception to be thrown
        except Exception as e:
            pytest.fail(f"Unexpected exception thrown: {e}")
