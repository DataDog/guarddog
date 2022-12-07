from typing import Optional

from .npm_package_scanner import NPMPackageScanner
from .npm_project_scanner import NPMRequirementsScanner
from .pypi_project_scanner import PypiRequirementsScanner
from .scanner import Scanner
from .pypi_package_scanner import PypiPackageScanner


def get_scanner(ecosystem: str, project: bool) -> Optional[Scanner]:
    match(ecosystem, project):
        case("pypi", False):
            return PypiPackageScanner()
        case("pypi", True):
            return PypiRequirementsScanner()
        case("npm", False):
            return NPMPackageScanner()
        case("npm", True):
            return NPMRequirementsScanner()
    return None
