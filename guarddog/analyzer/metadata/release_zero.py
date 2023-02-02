from guarddog.analyzer.metadata.detector import Detector


class ReleaseZeroDetector(Detector):
    """This heuristic detects if the latest release of this package is version 0."""

    MESSAGE_TEMPLATE = "The package has its latest release version to %s"

    def __init__(self):
        super().__init__(
            name="release_zero",
            description="Identify packages with an release version that's 0.0 or 0.0.0"
        )
