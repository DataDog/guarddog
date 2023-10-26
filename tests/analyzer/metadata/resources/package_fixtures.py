import pytest 
from copy import deepcopy
from tests.analyzer.metadata.resources import sample_project_info

@pytest.fixture
def pypi_package_info():
    return deepcopy(sample_project_info.PYPI_PACKAGE_INFO)

@pytest.fixture
def npm_package_info():
    return deepcopy(sample_project_info.NPM_PACKAGE_INFO)