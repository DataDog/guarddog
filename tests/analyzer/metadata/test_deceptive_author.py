import json
import os
import pathlib
import pytest

import guarddog.analyzer.metadata.utils
from guarddog.analyzer.metadata.npm.deceptive_author import NPMDeceptiveAuthor
from guarddog.analyzer.metadata.pypi.deceptive_author import PypiDeceptiveAuthor
from tests.analyzer.metadata.resources.sample_project_info import (
    generate_pypi_project_info,
    generate_npm_project_info,
)

from tests.analyzer.metadata.utils import MockWhoIs

pypi_detector = PypiDeceptiveAuthor()
npm_detector = NPMDeceptiveAuthor()


# required because mocking in tests will cause get_domain_creation_date()
# to return different results for a same domain
@pytest.fixture(autouse=True)
def clear_caches():
    guarddog.analyzer.metadata.utils.get_domain_creation_date.cache_clear()


class TestDeceptiveAuthor:

    disposable_author_pypi = generate_pypi_project_info(
        "author_email", "john@example.com"
    )
    disposable_author_npm = generate_npm_project_info(
        "maintainers", [{"name": "john doe", "email": "john@example.com"}]
    )
    non_disposable_author_pypi = generate_pypi_project_info(
        "author_email", "john@gmail.com"
    )
    non_disposable_author_npm = generate_npm_project_info(
        "maintainers", [{"name": "john doe", "email": "john@gmail.com"}]
    )

    @pytest.mark.parametrize(
        "package_info, detector",
        [
            (disposable_author_pypi, pypi_detector),
            (disposable_author_npm, npm_detector),
        ],
    )
    def test_disposable_email(self, package_info, detector):
        compromised, x = detector.detect(package_info)
        assert compromised

    @pytest.mark.parametrize(
        "package_info, detector",
        [
            (non_disposable_author_pypi, pypi_detector),
            (non_disposable_author_npm, npm_detector),
        ],
    )
    def test_non_disposable_email(self, package_info, detector):
        compromised, _ = detector.detect(package_info)
        assert not compromised
