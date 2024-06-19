from guarddog.analyzer.metadata.npm.empty_information import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.npm.release_zero import NPMReleaseZeroDetector
from guarddog.analyzer.metadata.npm.typosquatting import NPMTyposquatDetector
from guarddog.analyzer.metadata.npm.direct_url_dependency import (
    NPMDirectURLDependencyDetector,
)
from guarddog.analyzer.metadata.npm.npm_metadata_mismatch import NPMMetadataMismatch
from guarddog.analyzer.metadata.npm.bundled_binary import NPMBundledBinary
from guarddog.analyzer.metadata.npm.deceptive_author import NPMDeceptiveAuthor

NPM_METADATA_RULES = {}

classes = [
    NPMEmptyInfoDetector,
    NPMReleaseZeroDetector,
    NPMTyposquatDetector,
    NPMDirectURLDependencyDetector,
    NPMMetadataMismatch,
    NPMBundledBinary,
    NPMDeceptiveAuthor,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    NPM_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
