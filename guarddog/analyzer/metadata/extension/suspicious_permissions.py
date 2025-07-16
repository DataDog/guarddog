from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class ExtensionSuspiciousPermissionsDetector(Detector):
    """Detects extensions with suspicious permissions or capabilities"""

    def __init__(self):
        super().__init__(
            name="suspicious-permissions",
            description="Identify extensions with potentially dangerous permissions or suspicious characteristics"
        )

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, Optional[str]]:
        
        if not package_info or not isinstance(package_info, dict):
            return False, None
        
        manifest = package_info.get("manifest", {})
        marketplace = package_info.get("marketplace", {})
        source = package_info.get("source", "unknown")
        
        return self._detect_with_metadata(manifest, marketplace, source)
    
    def _detect_with_metadata(self, manifest: dict, marketplace: dict, source: str) -> tuple[bool, Optional[str]]:
        
        # Check manifest for suspicious activation events
        activation_events = manifest.get("activationEvents", [])
        suspicious_activations = []
        
        for event in activation_events:
            if isinstance(event, str):
                # Very broad activation events that could be suspicious
                if event == "*":
                    suspicious_activations.append(event)
                elif "onFileSystem:" in event and "*" in event:
                    suspicious_activations.append(event)
        
        if suspicious_activations:
            return True, f"Extension uses suspicious activation events: {', '.join(suspicious_activations)}"
        
        # Check for suspicious scripts in manifest
        scripts = manifest.get("scripts", {})
        if scripts:
            suspicious_script_patterns = ['rm -rf', 'del /s', 'format', 'shutdown', 'curl', 'wget', 'powershell']
            for script_name, script_content in scripts.items():
                if isinstance(script_content, str):
                    for pattern in suspicious_script_patterns:
                        if pattern in script_content.lower():
                            return True, f"Extension has suspicious script '{script_name}': contains '{pattern}'"
        
        dependencies = manifest.get("dependencies", {})
        dev_dependencies = manifest.get("devDependencies", {})
        all_deps = {**dependencies, **dev_dependencies}
        
        # The list is NOT exhaustive, adjust as needed
        suspicious_deps = ['child_process', 'fs-extra', 'shelljs', 'node-pty']
        found_suspicious_deps = [dep for dep in all_deps.keys() if any(sus in dep for sus in suspicious_deps)]
        
        if found_suspicious_deps:
            return True, f"Extension uses potentially dangerous dependencies: {', '.join(found_suspicious_deps[:3])}"
        
        if marketplace and source == "remote":
            download_count = marketplace.get("download_count", 0)            
            # Check if publisher is not verified but has high privileges
            publisher_info = marketplace.get("publisher", {})
            if isinstance(publisher_info, dict):
                flags = publisher_info.get("flags", [])
                is_verified = any("verified" in str(flag).lower() for flag in flags) if flags else False
                is_domain_verified = marketplace.get("publisher_isDomainVerified", False)
                
                # Suspicious: unverified publisher with low download count
                if not is_verified and not is_domain_verified and download_count < 1000:
                    return True, "Extension from unverified publisher with low download count"
                
                if flags:
                    flag_strings = [str(flag).lower() for flag in flags]
                    suspicious_flag_patterns = ['preview', 'deprecated', 'malware']  # malware might unnecessary since extensions are swiftly removed from the marketplace
                    found_suspicious_flags = [flag for flag in flag_strings 
                                            if any(pattern in flag for pattern in suspicious_flag_patterns)]
                    if found_suspicious_flags:
                        return True, f"Extension has suspicious marketplace flags: {', '.join(found_suspicious_flags)}"
        
        contributes = manifest.get("contributes", {})
        if contributes:
            # Check for dangerous contribution points
            if contributes.get("terminal"):
                return True, "Extension contributes terminal functionality which could be dangerous"
            
            if contributes.get("taskDefinitions"):
                return True, "Extension contributes task definitions which could execute arbitrary commands"
        
        # Will add typosquatting checks for most used commands 

        # Check categories for suspicious types
        categories = manifest.get("categories", [])
        if categories:
            suspicious_categories = ['debuggers', 'other', 'testing', 'snippets']
            category_strings = [str(cat).lower() for cat in categories]
            found_suspicious_cats = [cat for cat in category_strings 
                                   if any(sus in cat for sus in suspicious_categories)]
            if found_suspicious_cats and len(categories) == 1:
                # Only flag if it's the sole category
                return True, f"Extension has potentially suspicious sole category: {found_suspicious_cats[0]}"
        
        return False, None 