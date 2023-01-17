from guarddog.analyzer.metadata.utils.pypi.repository_cloner import PypiRepositoryCloner
from guarddog.ecosystems import ECOSYSTEM


class UtilBundle:

    def __init__(self, ecosystem, repository_cloner_class=None):
        self.ecosystem = ecosystem  # I am here for debugging reasons
        self.repository_cloner_class = repository_cloner_class


def get_util_bundle(ecosystem: ECOSYSTEM):
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return UtilBundle(
                ecosystem,
                repository_cloner_class=PypiRepositoryCloner
            )
        case ECOSYSTEM.NPM:
            return UtilBundle(
                ecosystem,
                repository_cloner_class=None
            )
