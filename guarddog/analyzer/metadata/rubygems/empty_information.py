import logging
from typing import Optional

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector

log = logging.getLogger("guarddog")


class RubyGemsEmptyInfoDetector(EmptyInfoDetector):
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        log.debug(f"Running RubyGems empty description heuristic on package {name}")
        info = package_info.get("info", "")
        if info is None:
            info = ""
        return (
            len(info.strip()) == 0,
            EmptyInfoDetector.MESSAGE_TEMPLATE % "RubyGems",
        )
