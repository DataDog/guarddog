from abc import abstractmethod
from typing import Optional


class Detector:
    RULE_NAME = ""

    def __init__(
        self,
        name: str,
        description: str,
        identifies: Optional[str] = None,
        severity: str = "medium",
        mitre_tactics: str = "",
        specificity: str = "medium",
        sophistication: str = "medium",
    ) -> None:
        self.name = name
        self.description = description
        self.identifies = identifies
        self.severity = severity
        self.mitre_tactics = mitre_tactics
        self.specificity = specificity
        self.sophistication = sophistication

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
