from typing import Type

from guarddog.analyzer.metadata import Detector
from guarddog.analyzer.metadata.rubygems.typosquatting import RubyGemsTyposquatDetector
from guarddog.analyzer.metadata.rubygems.empty_information import (
    RubyGemsEmptyInfoDetector,
)
from guarddog.analyzer.metadata.rubygems.release_zero import RubyGemsReleaseZeroDetector
from guarddog.analyzer.metadata.rubygems.bundled_binary import RubyGemsBundledBinary
from guarddog.analyzer.metadata.rubygems.repository_integrity_mismatch import (
    RubyGemsIntegrityMismatchDetector,
)

RUBYGEMS_METADATA_RULES = {}

classes: list[Type[Detector]] = [
    RubyGemsTyposquatDetector,
    RubyGemsEmptyInfoDetector,
    RubyGemsReleaseZeroDetector,
    RubyGemsBundledBinary,
    RubyGemsIntegrityMismatchDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    RUBYGEMS_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
