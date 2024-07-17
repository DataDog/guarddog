from typing import Optional

from .npm_package_scanner import NPMPackageScanner
from .npm_project_scanner import NPMRequirementsScanner
from .pypi_package_scanner import PypiPackageScanner
from .pypi_project_scanner import PypiRequirementsScanner
from .go_package_scanner import GoModuleScanner
from .go_project_scanner import GoDependenciesScanner
from .scanner import Scanner
from ..ecosystems import ECOSYSTEM


def get_scanner(ecosystem: ECOSYSTEM, project: bool) -> Optional[Scanner]:
    match (ecosystem, project):
        case (ECOSYSTEM.PYPI, False):
            return PypiPackageScanner()
        case (ECOSYSTEM.PYPI, True):
            return PypiRequirementsScanner()
        case (ECOSYSTEM.NPM, False):
            return NPMPackageScanner()
        case (ECOSYSTEM.NPM, True):
            return NPMRequirementsScanner()
        case (ECOSYSTEM.GO, False):
            return GoModuleScanner()
        case (ECOSYSTEM.GO, True):
            return GoDependenciesScanner()
    return None
