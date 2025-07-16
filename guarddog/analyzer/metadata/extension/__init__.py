from typing import Type

from guarddog.analyzer.metadata import Detector
from guarddog.analyzer.metadata.extension.empty_information import ExtensionEmptyInfoDetector
from guarddog.analyzer.metadata.extension.suspicious_publisher import ExtensionSuspiciousPublisherDetector
from guarddog.analyzer.metadata.extension.suspicious_permissions import ExtensionSuspiciousPermissionsDetector

EXTENSION_METADATA_RULES = {}

classes: list[Type[Detector]] = [
    ExtensionEmptyInfoDetector,
    ExtensionSuspiciousPublisherDetector,
    ExtensionSuspiciousPermissionsDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    EXTENSION_METADATA_RULES[detectorInstance.get_name()] = detectorInstance 