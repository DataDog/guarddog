from guarddog.analyzer.metadata.npm.empty_information import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.npm.potentially_compromised_email_domain import (
    NPMPotentiallyCompromisedEmailDomainDetector,
)
from guarddog.analyzer.metadata.npm.release_zero import NPMReleaseZeroDetector
from guarddog.analyzer.metadata.npm.typosquatting import NPMTyposquatDetector
from guarddog.analyzer.metadata.npm.direct_url_dependency import (
    NPMDirectURLDependencyDetector,
)
from guarddog.analyzer.metadata.npm.npm_metadata_mismatch import NPMMetadataMismatch

NPM_METADATA_RULES = {}

classes = [
    NPMEmptyInfoDetector,
    NPMReleaseZeroDetector,
    NPMPotentiallyCompromisedEmailDomainDetector,
    NPMTyposquatDetector,
    NPMDirectURLDependencyDetector,
    NPMMetadataMismatch,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    NPM_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
