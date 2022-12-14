from guarddog.analyzer.metadata.pypi.empty_information import PypiEmptyInfoDetector
from guarddog.analyzer.metadata.pypi.potentially_compromised_email_domain import \
    PypiPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.pypi.release_zero import PypiReleaseZeroDetector
from guarddog.analyzer.metadata.pypi.typosquatting import PypiTyposquatDetector

PYPI_METADATA_RULES = {}

classes = [
    PypiEmptyInfoDetector,
    PypiReleaseZeroDetector,
    PypiTyposquatDetector,
    PypiPotentiallyCompromisedEmailDomainDetector
]

for cls in classes:
    parent = cls.__base__
    PYPI_METADATA_RULES[parent.RULE_NAME] = cls()  # type: ignore
