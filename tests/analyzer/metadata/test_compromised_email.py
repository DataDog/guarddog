from datetime import datetime

from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.compromised_email import \
    CompromisedEmailDetector
from tests.analyzer.metadata.resources.sample_project_info import PACKAGE_INFO


class MockWhoIs():
    def __init__(self, date) -> None:
        self.creation_date = date


class TestCompromisedEmail():
    detector = CompromisedEmailDetector()
    
    
    def test_compromised(self):
        def mock_whois(domain):
            return MockWhoIs(datetime.today())
        
        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised = self.detector.detect(PACKAGE_INFO)
        assert compromised
    
    
    def test_safe(self):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))
        
        MonkeyPatch().setattr("whois.whois", mock_whois)
        compromised = self.detector.detect(PACKAGE_INFO)
        assert not compromised
        