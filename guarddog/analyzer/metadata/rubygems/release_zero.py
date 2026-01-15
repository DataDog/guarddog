import logging
from typing import Optional

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector

log = logging.getLogger("guarddog")


class RubyGemsReleaseZeroDetector(ReleaseZeroDetector):
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        log.debug(f"Running zero version heuristic on RubyGems package {name}")
        gem_version = package_info.get("version", "")
        return (
            gem_version in ["0.0.0", "0.0"],
            ReleaseZeroDetector.MESSAGE_TEMPLATE % gem_version,
        )
