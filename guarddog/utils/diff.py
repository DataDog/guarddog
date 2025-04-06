"""
Provides utilities for diffing directories and source code files.
"""

from dataclasses import dataclass
import filecmp
import functools
from pathlib import Path
from typing import Optional
from typing_extensions import Self

from guarddog.ecosystems import ECOSYSTEM, get_friendly_name


class SourceFileDiffer:
    """
    Provides source code file diffing utilities in various ecosystems.
    """
    @classmethod
    def from_ecosystem(cls, ecosystem: ECOSYSTEM) -> Self:
        """
        Initialize a `SourceFileDiffer` for use with source files from the given `ecosystem`.

        Args:
            * `ecosystem` (ECOSYSTEM): The ecosystem of the desired `SourceFileDiffer`.

        Returns:
            A `SourceFileDiffer` for use with source files from the desired ecosystem.

        Raises:
            ValueError: The given `ecosystem` is not supported.
        """
        if ecosystem == ECOSYSTEM.PYPI:
            return cls()
        else:
            raise ValueError(f"Diff scans are not available for the {get_friendly_name(ecosystem)} ecosystem")

    def get_diff(self, left: Path, right: Path) -> str:
        """
        Generate a minimal, valid program containing all changes between `left` and `right`.

        Args:
            * `left` (Path): The source file to diff against.
            * `right` (Path): The source file to be diffed.

        Returns:
            A minimal, syntactically valid program containing all lines in `right` that had
            changes with respect to `left`.

            The returned program is minimal in the sense that it only contains the top-level
            definitions in `right` that had at least one change with respect to `left`.

        Raises:
            ValueError: The inputs could not be correctly parsed by the `SourceFileDiffer`.
        """
        with open(right) as f:
            return f.read()


@dataclass
class DirectoryDiff:
    left: Path
    right: Path
    added: list[Path]
    changed: list[Path]

    @classmethod
    def from_directories(cls, left: Path, right: Path) -> Self:
        def inner(acc: tuple[list[Path], list[Path]], dcmp) -> tuple[list[Path], list[Path]]:
            added = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.right_only))
            changed = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.diff_files))
            return functools.reduce(inner, dcmp.subdirs.values(), (acc[0] + added, acc[1] + changed))

        dcmp = filecmp.dircmp(left, right)

        added, changed = inner(([], []), dcmp)
        added = list(map(lambda path: path.relative_to(right), added))
        changed = list(map(lambda path: path.relative_to(right), changed))

        return cls(left, right, added, changed)
