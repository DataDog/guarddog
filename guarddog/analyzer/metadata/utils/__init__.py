from guarddog.analyzer.metadata.utils.pypi.repository_cloner import PypiRepositoryCloner
from guarddog.ecosystems import ECOSYSTEM


class UtilBundle:

    def __init__(self, ecosystem, repository_cloner=None):
        self.ecosystem = ecosystem  # I am here for debugging reasons
        self.repository_cloner = repository_cloner


def get_util_bundle(ecosystem: ECOSYSTEM, package_info, name):
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return UtilBundle(
                ecosystem,
                repository_cloner=PypiRepositoryCloner(package_info=package_info, name=name)
            )
        case ECOSYSTEM.NPM:
            return UtilBundle(
                ecosystem,
                repository_cloner=None
            )
