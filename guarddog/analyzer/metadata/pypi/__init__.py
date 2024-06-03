from guarddog.analyzer.metadata.pypi.empty_information import PypiEmptyInfoDetector
from guarddog.analyzer.metadata.pypi.potentially_compromised_email_domain import \
    PypiPotentiallyCompromisedEmailDomainDetector
from guarddog.analyzer.metadata.pypi.unclaimed_maintainer_email_domain import \
    PypiUnclaimedMaintainerEmailDomainDetector
from guarddog.analyzer.metadata.pypi.release_zero import PypiReleaseZeroDetector
from guarddog.analyzer.metadata.pypi.repository_integrity_mismatch import PypiIntegrityMismatchDetector
from guarddog.analyzer.metadata.pypi.single_python_file import PypiSinglePythonFileDetector
from guarddog.analyzer.metadata.pypi.typosquatting import PypiTyposquatDetector
from guarddog.analyzer.metadata.pypi.bundled_binary import PypiBundledBinary
from guarddog.analyzer.metadata.pypi.deceptive_author import PypiDeceptiveAuthor

PYPI_METADATA_RULES = {}

classes = [
    PypiEmptyInfoDetector,
    PypiReleaseZeroDetector,
    PypiTyposquatDetector,
    PypiPotentiallyCompromisedEmailDomainDetector,
    PypiUnclaimedMaintainerEmailDomainDetector,
    PypiIntegrityMismatchDetector,
    PypiSinglePythonFileDetector,
    PypiBundledBinary,
    PypiDeceptiveAuthor,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    PYPI_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
