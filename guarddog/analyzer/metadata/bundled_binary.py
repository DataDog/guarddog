from abc import abstractmethod
import hashlib
import logging
import os
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector

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
        def format_file(file: str, kind: str) -> str:
            return f"{file} ({kind})"

        def sha256(file: str) -> str:
            with open(file, "rb") as f:
                hasher = hashlib.sha256()
                while (chunk := f.read(4096)):
                    hasher.update(chunk)
                return hasher.hexdigest()

        log.debug(
            f"Running bundled binary heuristic on package {name} version {version}"
        )
        if not path:
            raise ValueError("path is needed to run heuristic " + self.get_name())

        bin_files = {}
        for root, _, files in os.walk(path):
            for f in files:
                path = os.path.join(root, f)
                kind = self.is_binary(path)
                if kind:
                    digest = sha256(path)
                    if digest not in bin_files:
                        bin_files[digest] = [format_file(f, kind)]
                    else:
                        bin_files[digest].append(format_file(f, kind))

        if not bin_files:
            return False, ""

        output_lines = '\n'.join(
            f"{digest}: {', '.join(files)}" for digest, files in bin_files.items()
        )
        return True, f"Binary file/s detected in package:\n{output_lines}"

    def is_binary(self, path: str) -> Optional[str]:
        max_head = len(max(self.magic_bytes.values()))
        with open(os.path.join(path), "rb") as fd:
            header: bytes = fd.read(max_head)
            for k, v in self.magic_bytes.items():
                if header[: len(v)] == v:
                    return k
        return None
