from abc import abstractmethod
from typing import Optional


class Detector:

    RULE_NAME = ""

    def __init__(self) -> None:
        pass

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(self, package_info, path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        pass  # pragma: no cover
