from datetime import datetime

from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.potentially_compromised_email_domain import PotentiallyCompromisedEmailDomainDetector
from tests.analyzer.metadata.resources.sample_npm_project_info import NPM_PACKAGE_INFO
from tests.analyzer.metadata.resources.sample_project_info import PACKAGE_INFO


class MockWhoIs:
    def __init__(self, date) -> None:
        self.creation_date = date


class TestCompromisedEmail:
    detector = PotentiallyCompromisedEmailDomainDetector()

    def test_compromised(self):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(PACKAGE_INFO, "pypi")
        assert compromised

    def test_safe(self):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(PACKAGE_INFO, "pypi")
        assert not compromised
        compromised, _ = self.detector.detect(NPM_PACKAGE_INFO, "npm")
        assert not compromised

    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            import whois
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised, _ = self.detector.detect(PACKAGE_INFO, "pypi")
        assert compromised
