from abc import abstractmethod
from typing import Optional


class Detector:
    def __init__(self) -> None:
        pass

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(self, package_info, ecosystem: str) -> tuple[bool, Optional[str]]:  # pragma: no cover
        pass
