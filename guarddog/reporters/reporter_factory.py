from enum import Enum, auto
from typing import Optional

from guarddog.reporters import BaseReporter
from guarddog.reporters.human_readable import HumanReadableReporter
from guarddog.reporters.sarif import SarifReporter
from guarddog.reporters.json import JsonReporter


class ReporterType(Enum):
    """
    Enum representing the different types of reporters available.
    """

    HUMAN_READABLE = auto()
    SARIF = auto()
    JSON = auto()

    @classmethod
    def from_str(cls, type: Optional[str]) -> "ReporterType":
        if not type:
            return cls.HUMAN_READABLE
        match (type).lower():
            case "human_readable":
                return cls.HUMAN_READABLE
            case "sarif":
                return cls.SARIF
            case "json":
                return cls.JSON
            case _:
                raise ValueError(f"Unsupported reporter type: {type}")


class ReporterFactory:
    """
    Factory class for creating reporter instances based on the reporter type.
    """

    @staticmethod
    def create_reporter(reporter_type: ReporterType) -> type[BaseReporter]:
        """
        Create a reporter instance based on the reporter type.
        """
        match reporter_type:
            case ReporterType.HUMAN_READABLE:
                return HumanReadableReporter
            case ReporterType.SARIF:
                return SarifReporter
            case ReporterType.JSON:
                return JsonReporter
