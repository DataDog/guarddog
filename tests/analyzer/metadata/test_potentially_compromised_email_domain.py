import json
import os
import pathlib
from datetime import datetime

import pytest
from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.npm import NPMPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.pypi import PypiPotentiallyCompromisedEmailDomainDetector
from tests.analyzer.metadata.resources.sample_project_info import PACKAGE_INFO

with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "npm_data.json"), "r") as file:
    NPM_PACKAGE_INFO = json.load(file)


class MockWhoIs:
    def __init__(self, date) -> None:
        self.creation_date = date


pypi_detector = PypiPotentiallyCompromisedEmailDomainDetector()
npm_detector = NPMPotentiallyCompromisedEmailDomainDetector()


class TestCompromisedEmail:

    @pytest.mark.parametrize("package_info, detector", [(PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
    def test_compromised(self, package_info, detector):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = detector.detect(package_info)
        assert compromised

    @pytest.mark.parametrize("package_info, detector", [(PACKAGE_INFO, pypi_detector), (NPM_PACKAGE_INFO, npm_detector)])
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
        compromised, _ = pypi_detector.detect(PACKAGE_INFO)
        assert compromised
