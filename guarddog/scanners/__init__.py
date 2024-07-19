from typing import Optional

from .npm_package_scanner import NPMPackageScanner
from .npm_project_scanner import NPMRequirementsScanner
from .pypi_package_scanner import PypiPackageScanner
from .pypi_project_scanner import PypiRequirementsScanner
from .go_package_scanner import GoModuleScanner
from .go_project_scanner import GoDependenciesScanner
from .scanner import PackageScanner, ProjectScanner
from ..ecosystems import ECOSYSTEM


def get_package_scanner(ecosystem: ECOSYSTEM) -> Optional[PackageScanner]:
    """
    TODO

    Args:
        ecosystem (ECOSYSTEM): TODO

    Returns:
        Optional[PackageScanner]: TODO
    """
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return PypiPackageScanner()
        case ECOSYSTEM.NPM:
            return NPMPackageScanner()
        case ECOSYSTEM.GO:
            return GoModuleScanner()
    return None


def get_project_scanner(ecosystem: ECOSYSTEM) -> Optional[ProjectScanner]:
    """
    TODO

    Args:
        ecosystem (ECOSYSTEM): TODO

    Returns:
        Optional[ProjectScanner]: TODO
    """
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return PypiRequirementsScanner()
        case ECOSYSTEM.NPM:
            return NPMRequirementsScanner()
        case ECOSYSTEM.GO:
            return GoDependenciesScanner()
    return None
