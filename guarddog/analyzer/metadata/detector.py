from abc import abstractmethod
from typing import Optional


class Detector:
    RULE_NAME = ""

    def __init__(
        self,
        name: str,
        description: str,
        help_url: Optional[str] = None,
        verbose_description: Optional[str] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.help_url = help_url
        self.verbose_description = verbose_description

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        pass  # pragma: no cover

    def get_name(self) -> str:
        return self.name

    def get_description(self) -> str:
        return self.description
