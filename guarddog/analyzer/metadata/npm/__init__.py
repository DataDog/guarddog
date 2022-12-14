from guarddog.analyzer.metadata.npm.empty_information import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.npm.potentially_compromised_email_domain import \
    NPMPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.npm.release_zero import NPMReleaseZeroDetector

NPM_METADATA_RULES = {}

classes = [
    NPMEmptyInfoDetector,
    NPMReleaseZeroDetector,
    NPMPotentiallyCompromisedEmailDomainDetector
]

for cls in classes:
    parent = cls.__base__
    NPM_METADATA_RULES[parent.RULE_NAME] = cls()  # type: ignore
