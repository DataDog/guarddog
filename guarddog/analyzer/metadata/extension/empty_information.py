""" Empty Information Detector for Extensions

Detects if an extension contains an empty description
"""
import logging
from typing import Optional

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector

log = logging.getLogger("guarddog")


class ExtensionEmptyInfoDetector(EmptyInfoDetector):
    """Detects extensions with empty description information"""

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        
        log.debug(f"Running extension empty description heuristic on extension {name} version {version}")
        
        if not package_info or not isinstance(package_info, dict):
            return True, "Extension has no package information"
        
        manifest = package_info.get("manifest", {})
        marketplace = package_info.get("marketplace", {})
        source = package_info.get("source", "unknown")
        
        return self._detect_with_metadata(manifest, marketplace, source)
    
    def _detect_with_metadata(self, manifest: dict, marketplace: dict, source: str) -> tuple[bool, str]:
        """Detect empty information with pre-extracted metadata"""
        
        manifest_description = manifest.get("description", "").strip()
        manifest_display_name = manifest.get("displayName", "").strip()
        
        if not manifest_description and not manifest_display_name:
            return True, self.MESSAGE_TEMPLATE % "Extension Marketplace (manifest)"
        return False, ""