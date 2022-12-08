from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Optional
    from .scanner import Scanner


def get_scanner(ecosystem: str, project: bool) -> Optional[Scanner]:
    match (ecosystem, project):
        case ("pypi", False):
            from .pypi_package_scanner import PypiPackageScanner
            return PypiPackageScanner()
        case ("pypi", True):
            from .pypi_project_scanner import PypiRequirementsScanner
            return PypiRequirementsScanner()
        case ("npm", False):
            from .npm_package_scanner import NPMPackageScanner
            return NPMPackageScanner()
        case ("npm", True):
            from .npm_project_scanner import NPMRequirementsScanner
            return NPMRequirementsScanner()
    return None
