from datetime import datetime
import json
import os
import pathlib

from _pytest.monkeypatch import MonkeyPatch
import pytest

from guarddog.analyzer.metadata.pypi import PypiUnclaimedMaintainerEmailDomainDetector
import guarddog.analyzer.metadata.utils
from tests.analyzer.metadata.resources.sample_project_info import PYPI_PACKAGE_INFO

from tests.analyzer.metadata.utils import MockWhoIs


with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "npm_data.json"), "r") as file:
    NPM_PACKAGE_INFO = json.load(file)

pypi_detector = PypiUnclaimedMaintainerEmailDomainDetector()

# required because mocking in tests will cause get_domain_creation_date()
# to return different results for a same domain
@pytest.fixture(autouse=True)
def clear_caches():
    guarddog.analyzer.metadata.utils.get_domain_creation_date.cache_clear()

class TestUnclaimedMaintainerEmailDomain:
    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            import whois
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        # should work exactly the same for NPM
        compromised, _ = pypi_detector.detect(PYPI_PACKAGE_INFO)
        assert compromised

    def test_email_domain_does_exist(self):
        def mock_whois(domain):
            return MockWhoIs(datetime(1990, 1, 31))

        MonkeyPatch().setattr("whois.whois", mock_whois)
        # should work exactly the same for NPM
        compromised, _ = pypi_detector.detect(PYPI_PACKAGE_INFO)
        assert not compromised
