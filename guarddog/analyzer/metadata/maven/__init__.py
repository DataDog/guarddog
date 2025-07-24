# Maven-specific metadata security rules

from guarddog.analyzer.metadata.maven.typosquatting import MavenTyposquatDetector

MAVEN_METADATA_RULES = {}

classes = [
    MavenTyposquatDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
