import json
import os
import pathlib

import pytest
from _pytest.monkeypatch import MonkeyPatch

from guarddog.analyzer.metadata.pypi import PypiUnclaimedMaintainerEmailDomainDetector
from tests.analyzer.metadata.resources.sample_project_info import PYPI_PACKAGE_INFO

with open(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "npm_data.json"), "r") as file:
    NPM_PACKAGE_INFO = json.load(file)

pypi_detector = PypiUnclaimedMaintainerEmailDomainDetector()


class TestUnclaimedMaintainerEmailDomain:
    def test_email_domain_doesnt_exist(self):
        def mock_whois(domain):
            import whois
            raise whois.parser.PywhoisError('No match for "nope.com".')

        MonkeyPatch().setattr("whois.whois", mock_whois)
        # should work exactly the same for NPM
        compromised, _ = pypi_detector.detect(PYPI_PACKAGE_INFO)
        assert compromised
