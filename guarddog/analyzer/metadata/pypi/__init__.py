from guarddog.analyzer.metadata.pypi.potentially_compromised_email_domain import (
    PypiPotentiallyCompromisedEmailDomainDetector,
)
from guarddog.analyzer.metadata.pypi.unclaimed_maintainer_email_domain import (
    PypiUnclaimedMaintainerEmailDomainDetector,
)
from guarddog.analyzer.metadata.pypi.repository_integrity_mismatch import (
    PypiIntegrityMismatchDetector,
)
from guarddog.analyzer.metadata.pypi.typosquatting import PypiTyposquatDetector
from guarddog.analyzer.metadata.pypi.bundled_binary import PypiBundledBinary
from guarddog.analyzer.metadata.pypi.deceptive_author import PypiDeceptiveAuthor
from guarddog.analyzer.metadata.pypi.metadata_mismatch import (
    PypiMetadataMismatchDetector,
)

PYPI_METADATA_RULES = {}

classes = [
    PypiTyposquatDetector,
    PypiPotentiallyCompromisedEmailDomainDetector,
    PypiUnclaimedMaintainerEmailDomainDetector,
    PypiIntegrityMismatchDetector,
    PypiBundledBinary,
    PypiDeceptiveAuthor,
    PypiMetadataMismatchDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    PYPI_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
