import os
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

THRESHOLD = 1


class PypiSinglePythonFileDetector(Detector):

    def __init__(self):
        super().__init__(
            name="single_python_file",
            description="Identify packages that have only a single Python file"
        )

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, Optional[str]]:
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())
        matches = self._has_fewer_than_threshold_python_files(path)
        return matches, f"This package has {THRESHOLD} or fewer Python source files"

    def _has_fewer_than_threshold_python_files(self, path: str) -> bool:
        # We could use something like the below instead:
        # matches = len(glob(f"{path}/**/*.py", recursive=True)) <= THRESHOLD
        # but it would allegedly be slower since it needs to traverse the whole directory
        num_python_files = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.py'):
                    num_python_files += 1
                if num_python_files > THRESHOLD:
                    return False
        return True
