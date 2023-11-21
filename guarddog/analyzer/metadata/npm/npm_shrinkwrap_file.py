from typing import Optional
from pathlib import Path

from guarddog.analyzer.metadata.detector import Detector

class NPMShrinkwrapFile(Detector):
    def __init__(self):
        super().__init__(
            name="npm_shrinkwrap_file",
            description="Identify packages with a npm-shrinkwrap.json file which prevents end users from updating transitive dependencies."
        )

    def detect(
            self,
            package_info,
            path: Optional[str] = None,
            name: Optional[str] = None,
            version: Optional[str] = None,
            ) -> tuple[bool, Optional[str]]:
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())

        if Path(path).joinpath(Path("package", "npm-shrinkwrap.json")).is_file():
            return True, "A npm-shrinkwrap.json file was found in the package."
        else:
            return False, None
