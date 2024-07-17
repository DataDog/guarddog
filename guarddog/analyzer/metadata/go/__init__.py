from guarddog.analyzer.metadata import Detector

GO_METADATA_RULES = {}

classes: list[Detector] = []

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    GO_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
