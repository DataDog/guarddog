from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class MetadataMismatchDetector(Detector):
    """Detects mismatches between a package's registry metadata and its actual manifest file.

    This catches supply chain attacks where the registry metadata (dependencies, scripts,
    entry points) differs from what's declared inside the package itself.
    """

    def __init__(self):
        super().__init__(
            name="metadata_mismatch",
            description="Identify packages with mismatches between registry metadata"
            " and the actual package manifest",
            identifies="threat.metadata.manifest-mismatch",
            severity="medium",
            mitre_tactics="execution",
            specificity="medium",
            sophistication="medium",
        )

    @abstractmethod
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        pass  # pragma: no cover
