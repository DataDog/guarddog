from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.utils import UtilBundle


class Detector:

    RULE_NAME = ""

    def __init__(self) -> None:
        pass

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(
            self,
            package_info,
            path: Optional[str] = None,
            name: Optional[str] = None,
            version: Optional[str] = None,
            utils_bundle: Optional[UtilBundle] = None,
    ) -> tuple[bool, Optional[str]]:
        pass  # pragma: no cover
