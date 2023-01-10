from guarddog.analyzer.metadata.npm.empty_information import NPMEmptyInfoDetector
from guarddog.analyzer.metadata.npm.potentially_compromised_email_domain import \
    NPMPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.npm.release_zero import NPMReleaseZeroDetector
from guarddog.analyzer.metadata.npm.typosquatting import NPMTyposquatDetector

NPM_METADATA_RULES = {}

classes = [
    NPMEmptyInfoDetector,
    NPMReleaseZeroDetector,
    NPMPotentiallyCompromisedEmailDomainDetector,
    NPMTyposquatDetector
]

for cls in classes:
    parent = cls.__base__
    NPM_METADATA_RULES[parent.RULE_NAME] = cls()  # type: ignore
