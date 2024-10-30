from typing import Type

from guarddog.analyzer.metadata import Detector
from guarddog.analyzer.metadata.go.typosquatting import GoTyposquatDetector

GO_METADATA_RULES = {}

classes: list[Type[Detector]] = [
    GoTyposquatDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    GO_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
