from guarddog.analyzer.metadata.detector import Detector
from guarddog.ecosystems import ECOSYSTEM


def get_metadata_detectors(ecosystem: ECOSYSTEM) -> dict[str, Detector]:
    match (ecosystem):
        case ECOSYSTEM.PYPI:
            from guarddog.analyzer.metadata.pypi import PYPI_METADATA_RULES
            return PYPI_METADATA_RULES
        case ECOSYSTEM.NPM:
            from guarddog.analyzer.metadata.npm import NPM_METADATA_RULES
            return NPM_METADATA_RULES
        case ECOSYSTEM.GO:
            from guarddog.analyzer.metadata.go import GO_METADATA_RULES
            return GO_METADATA_RULES
        case ECOSYSTEM.GITHUB_ACTION:
            from guarddog.analyzer.metadata.github_action import GITHUB_ACTION_METADATA_RULES
            return GITHUB_ACTION_METADATA_RULES
        case ECOSYSTEM.EXTENSION:
            return {}  # No metadata detectors for extensions currently
        case ECOSYSTEM.RUBYGEMS:
            from guarddog.analyzer.metadata.rubygems import RUBYGEMS_METADATA_RULES
            return RUBYGEMS_METADATA_RULES
        case ECOSYSTEM.MCP:
            from guarddog.analyzer.metadata.mcp import MCP_METADATA_RULES
            return MCP_METADATA_RULES
    return {}
