from guarddog.analyzer.metadata.detector import Detector
from abc import abstractmethod
from typing import Optional
import os
from functools import reduce
import logging

log = logging.getLogger("guarddog")


class BundledBinary(Detector):
    """This heuristic detects if the package includes bundles binary file."""

    # magic bytes are the first few bytes of a file that can be used to identify the file type
    # regardless of their extension
    magic_bytes = {"exe": b"\x4D\x5A", "elf": b"\x7F\x45\x4C\x46"}

    def __init__(self):
        super().__init__(
            name="bundled_binary", description="Identify packages bundling binaries"
        )

    @abstractmethod
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:

        log.debug(
            f"Running bundled binary heuristic on package {name} version {version}"
        )
        if not path:
            raise ValueError("path is needed to run heuristic " + self.get_name())

        bin_files = []
        for root, _, files in os.walk(path):
            for f in files:
                kind = self.is_binary(os.path.join(root, f))
                if kind:
                    bin_files.append(f"{f} type {kind}")
        if bin_files:
            return True, "Binary file/s detected in package: " + reduce(lambda x, y: f"{x}, {y}", bin_files)
        return False, ""

    def is_binary(self, path: str) -> Optional[str]:
        max_head = len(max(self.magic_bytes.values()))
        with open(os.path.join(path), "rb") as fd:
            header: bytes = fd.read(max_head)
            for k, v in self.magic_bytes.items():
                if header[: len(v)] == v:
                    return k
        return None
