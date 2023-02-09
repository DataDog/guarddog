from guarddog.analyzer.metadata.pypi.empty_information import PypiEmptyInfoDetector
from guarddog.analyzer.metadata.pypi.potentially_compromised_email_domain import \
    PypiPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.pypi.release_zero import PypiReleaseZeroDetector
from guarddog.analyzer.metadata.pypi.repository_integrity_mismatch import PypiIntegrityMismatchDetector
from guarddog.analyzer.metadata.pypi.typosquatting import PypiTyposquatDetector

PYPI_METADATA_RULES = {}

classes = [
    PypiEmptyInfoDetector,
    PypiReleaseZeroDetector,
    PypiTyposquatDetector,
    PypiPotentiallyCompromisedEmailDomainDetector,
    PypiIntegrityMismatchDetector
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    PYPI_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
