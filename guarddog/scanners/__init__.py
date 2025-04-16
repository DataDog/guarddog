from typing import Optional

from .github_action_project_scanner import GitHubActionDependencyScanner
from .npm_package_scanner import NPMPackageScanner
from .npm_project_scanner import NPMRequirementsScanner
from .pypi_package_scanner import PypiPackageScanner
from .pypi_project_scanner import PypiRequirementsScanner
from .go_package_scanner import GoModuleScanner
from .go_project_scanner import GoDependenciesScanner
from .github_action_scanner import GithubActionScanner
from .scanner import PackageScanner, ProjectScanner
from .uv_lock_scanner import UVLockScanner
from ..ecosystems import ECOSYSTEM


def get_package_scanner(ecosystem: ECOSYSTEM) -> Optional[PackageScanner]:
    """
    Return a `PackageScanner` for the given ecosystem or `None` if it
    is not yet supported.

    Args:
        ecosystem (ECOSYSTEM): The ecosystem of the desired scanner

    Returns:
        Optional[PackageScanner]: The result of the scanner request

    """
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return PypiPackageScanner()
        case ECOSYSTEM.NPM:
            return NPMPackageScanner()
        case ECOSYSTEM.GO:
            return GoModuleScanner()
        case ECOSYSTEM.GITHUB_ACTION:
            return GithubActionScanner()
    return None


def get_project_scanner(ecosystem: ECOSYSTEM) -> Optional[ProjectScanner]:
    """
    Return a `ProjectScanner` for the given ecosystem or `None` if
    it is not yet supported.

    Args:
        ecosystem (ECOSYSTEM): The ecosystem of the desired scanner

    Returns:
        Optional[ProjectScanner]: The result of the scanner request

    """
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return PypiRequirementsScanner()
        case ECOSYSTEM.NPM:
            return NPMRequirementsScanner()
        case ECOSYSTEM.GO:
            return GoDependenciesScanner()
        case ECOSYSTEM.GITHUB_ACTION:
            return GitHubActionDependencyScanner()
        case ECOSYSTEM.UV:  
            return UVLockScanner()
    return None
