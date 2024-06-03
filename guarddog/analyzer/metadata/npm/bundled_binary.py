from guarddog.analyzer.metadata.bundled_binary import BundledBinary
from typing import Optional


class NPMBundledBinary(BundledBinary):
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        return super().detect(package_info, path, name, version)
