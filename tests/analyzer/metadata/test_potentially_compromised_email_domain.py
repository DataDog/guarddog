from datetime import datetime

import pytest
from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.potentially_compromised_email_domain import PotentiallyCompromisedEmailDomainDetector
from tests.analyzer.metadata.resources.sample_npm_project_info import NPM_PACKAGE_INFO
from tests.analyzer.metadata.resources.sample_project_info import PACKAGE_INFO


class MockWhoIs:
    def __init__(self, date) -> None:
        self.creation_date = date


class TestCompromisedEmail:
    detector = PotentiallyCompromisedEmailDomainDetector()

    @pytest.mark.parametrize("package_info, ecosystem", [(PACKAGE_INFO, "pypi"), (NPM_PACKAGE_INFO, "npm")])
    def test_compromised(self, package_info, ecosystem):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(package_info, ecosystem)
        assert compromised

    @pytest.mark.parametrize("package_info, ecosystem", [(PACKAGE_INFO, "pypi"), (NPM_PACKAGE_INFO, "npm")])
    def test_safe(self, package_info, ecosystem):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(package_info, ecosystem)
        assert not compromised

    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            import whois
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(PACKAGE_INFO, "pypi")
        assert compromised
