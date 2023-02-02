from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.npm import NPM_METADATA_RULES
from guarddog.analyzer.metadata.pypi import PYPI_METADATA_RULES
from guarddog.ecosystems import ECOSYSTEM


def get_metadata_detectors(ecosystem: ECOSYSTEM) -> dict[str, Detector]:
    match (ecosystem):
        case ECOSYSTEM.PYPI:
            return PYPI_METADATA_RULES
        case ECOSYSTEM.NPM:
            return NPM_METADATA_RULES
