from typing import Type

from guarddog.analyzer.metadata import Detector

GITHUB_ACTION_METADATA_RULES = {}

classes: list[Type[Detector]] = []

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    GITHUB_ACTION_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
