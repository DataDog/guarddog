from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class ExtensionSuspiciousPublisherDetector(Detector):
    """Detects extensions with suspicious publisher characteristics"""

    def __init__(self):
        super().__init__(name="suspicious-publisher",
                         description="Identify extensions with suspicious"
                         "publisher verification status and typosquatting")

    def detect(self,
               package_info,
               path: Optional[str] = None,
               name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool,
                                                       Optional[str]]:

        if not package_info or not isinstance(package_info, dict):
            return False, None

        manifest = package_info.get("manifest", {})
        marketplace = package_info.get("marketplace", {})
        source = package_info.get("source", "unknown")

        return self._detect_with_metadata(
            manifest, marketplace, source, package_info)

    def _detect_with_metadata(self,
                              manifest: dict,
                              marketplace: dict,
                              source: str,
                              package_info: dict) -> tuple[bool,
                                                           Optional[str]]:
        """Detect suspicious publisher patterns with pre-extracted metadata"""

        manifest_publisher = manifest.get("publisher", "").strip()

        if not manifest_publisher:
            return False, None  # Already handled by empty-information detector

        # TODO: Check for typosquatting using the dedicated detector

        verification_info = []
        if marketplace and source == "remote":
            publisher_info = marketplace.get("publisher", {})

            if isinstance(publisher_info, dict):
                # Check if publisher is verified (positive information)
                flags = publisher_info.get("flags", [])
                is_verified = any("verified" in str(flag).lower()
                                  for flag in flags) if flags else False

                if is_verified:
                    verification_info.append("Publisher is verified")

                # Check if publisher domain is verified (positive information)
                is_domain_verified = marketplace.get(
                    "publisher_isDomainVerified", False)
                if is_domain_verified:
                    verification_info.append("Publisher domain is verified")

        # If we have positive verification information, include it in a non-suspicious way
        # This doesn't return True (not suspicious) but provides information
        # until more robust heuristics are implemented
        if verification_info:
            pass

        return False, None
