from typing import Optional

from .npm_package_scanner import NPMPackageScanner
from .project_scanner import RequirementsScanner
from .scanner import Scanner
from .pypi_package_scanner import PypiPackageScanner


def get_scanner(ecosystem: str, project: bool) -> Optional[Scanner]:
    match (ecosystem, project):
        case ("pypi", False):
            return PypiPackageScanner()
        case ("pypi", True):
            return RequirementsScanner()
        case ("npm", False):
            return NPMPackageScanner()
    return None
