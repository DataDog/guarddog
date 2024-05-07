from guarddog.analyzer.metadata.npm.empty_information import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.npm.potentially_compromised_email_domain import (
    NPMPotentiallyCompromisedEmailDomainDetector,
)
from guarddog.analyzer.metadata.npm.unclaimed_maintainer_email_domain import (
    NPMUnclaimedMaintainerEmailDomainDetector,
)
from guarddog.analyzer.metadata.npm.release_zero import NPMReleaseZeroDetector
from guarddog.analyzer.metadata.npm.typosquatting import NPMTyposquatDetector
from guarddog.analyzer.metadata.npm.direct_url_dependency import (
    NPMDirectURLDependencyDetector,
)
from guarddog.analyzer.metadata.npm.npm_metadata_mismatch import NPMMetadataMismatch
from guarddog.analyzer.metadata.npm.bundled_binary import NPMBundledBinary

NPM_METADATA_RULES = {}

classes = [
    NPMEmptyInfoDetector,
    NPMReleaseZeroDetector,
    NPMPotentiallyCompromisedEmailDomainDetector,
    NPMUnclaimedMaintainerEmailDomainDetector,
    NPMTyposquatDetector,
    NPMDirectURLDependencyDetector,
    NPMMetadataMismatch,
    NPMBundledBinary,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    NPM_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
