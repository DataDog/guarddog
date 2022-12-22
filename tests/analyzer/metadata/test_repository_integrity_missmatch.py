import json
import os
import pathlib
from copy import deepcopy

import pytest

from guarddog.analyzer.metadata.pypi import PypiIntegrityMissmatch
from tests.analyzer.metadata.resources.sample_project_info import PACKAGE_INFO


def test_no_github_links():
    current_info = deepcopy(PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    detector = PypiIntegrityMissmatch()
    match, message = detector.detect(current_info)
    assert not match
    assert message == "Could not find any GitHub url in the project's description"


def test_no_good_github_links():
    current_info = deepcopy(PACKAGE_INFO)
    current_info["info"]["home_page"] = ""
    current_info["info"]["project_urls"]["Homepage"] = ""
    current_info["info"]["summary"] = "https://github.com/pypa/sampleproject"
    detector = PypiIntegrityMissmatch()
    match, message = detector.detect(current_info, name="mypackage")
    assert not match
    assert message == "Could not find a good GitHub url in the project's description"
