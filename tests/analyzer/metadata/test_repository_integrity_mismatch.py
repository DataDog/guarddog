from copy import deepcopy

from guarddog.analyzer.metadata.pypi import PypiIntegrityMismatchDetector
from tests.analyzer.metadata.resources.sample_project_info import PYPI_PACKAGE_INFO


def test_no_github_links():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="", path="")
    assert not match
    assert message == "Could not find any GitHub url in the project's description"


def test_no_good_homepage_link():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"] = {
        "Download": "UNKNOWN",
        "Homepage": "https://github.com/pypa/samplproject",
        },
    current_info["info"]["summary"] = "https://github.com/pypa/sampleproject"
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="mypackage", path="")
    assert not match
    assert message == "Could not find a good GitHub url in the project's description"

def test_no_good_github_links():
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    current_info["info"]["summary"] = "https://github.com/pypa/sampleproject"
    detector = PypiIntegrityMismatchDetector()
    match, message = detector.detect(current_info, name="mypackage", path="")
    assert not match
    assert message == "Could not find a good GitHub url in the project's description"


def test_empty_homepage_urls():
    """
    Regression test for https://github.com/DataDog/guarddog/issues/190
    """
    current_info = deepcopy(PYPI_PACKAGE_INFO)
    current_info["info"]["project_urls"] = None
    detector = PypiIntegrityMismatchDetector()
    match, _ = detector.detect(current_info, name="mypackage", path="")
    assert not match