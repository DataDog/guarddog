"""
Provides a representation of recursive directory diffs.
"""

from dataclasses import dataclass
import filecmp
import functools
from pathlib import Path
from typing_extensions import Self


@dataclass
class DirectoryDiff:
    left: Path
    right: Path
    added: list[Path]
    changed_files: list[Path]

    @classmethod
    def from_directories(cls, left: Path, right: Path) -> Self:
        def inner(acc: tuple[list[Path], list[Path]], dcmp) -> tuple[list[Path], list[Path]]:
            added = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.right_only))
            changed_files = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.diff_files))
            return functools.reduce(inner, dcmp.subdirs.values(), (acc[0] + added, acc[1] + changed_files))

        dcmp = filecmp.dircmp(left, right)

        added, changed_files = inner(([], []), dcmp)
        added = list(map(lambda path: path.relative_to(right), added))
        changed_files = list(map(lambda path: path.relative_to(right), changed_files))

        return cls(left, right, added, changed_files)
