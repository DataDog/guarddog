from abc import abstractmethod
from typing import Optional


class Detector:
    def __init__(self) -> None:
        pass

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(self, package_info, ecosystem: str, path: Optional[str] = None) -> tuple[bool, Optional[str]]:  # pragma: no cover
        pass
