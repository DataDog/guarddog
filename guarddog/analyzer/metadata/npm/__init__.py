from guarddog.analyzer.metadata.npm.potentially_compromised_email_domain import (
    NPMPotentiallyCompromisedEmailDomainDetector,
)
from guarddog.analyzer.metadata.npm.unclaimed_maintainer_email_domain import (
    NPMUnclaimedMaintainerEmailDomainDetector,
)
from guarddog.analyzer.metadata.npm.typosquatting import NPMTyposquatDetector
from guarddog.analyzer.metadata.npm.direct_url_dependency import (
    NPMDirectURLDependencyDetector,
)
from guarddog.analyzer.metadata.npm.metadata_mismatch import NPMMetadataMismatchDetector
from guarddog.analyzer.metadata.npm.bundled_binary import NPMBundledBinary
from guarddog.analyzer.metadata.npm.deceptive_author import NPMDeceptiveAuthor
from guarddog.analyzer.metadata.npm.risky_new_dependency import (
    NPMRiskyNewDependencyDetector,
)

NPM_METADATA_RULES = {}

classes = [
    NPMPotentiallyCompromisedEmailDomainDetector,
    NPMUnclaimedMaintainerEmailDomainDetector,
    NPMTyposquatDetector,
    NPMDirectURLDependencyDetector,
    NPMMetadataMismatchDetector,
    NPMBundledBinary,
    NPMDeceptiveAuthor,
    NPMRiskyNewDependencyDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    NPM_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
