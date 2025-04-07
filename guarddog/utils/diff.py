"""
Provides utilities for diffing directories and source code files.
"""

from dataclasses import dataclass
import filecmp
import functools
import logging
import os
from pathlib import Path
import shutil
import sys
from tree_sitter import Language, Node, Parser, Tree
import tree_sitter_go as ts_go
import tree_sitter_javascript as ts_javascript
import tree_sitter_python as ts_python
from typing_extensions import Self

from guarddog.ecosystems import ECOSYSTEM

log = logging.getLogger("guarddog")


class SourceCodeDiffer:
    """
    Provides source code diffing utilities parameterized over target language.
    """
    def __init__(self, parser: Parser):
        self._parser = parser

    @classmethod
    def from_ecosystem(cls, ecosystem: ECOSYSTEM) -> Self:
        """
        Initialize a `SourceCodeDiffer` for use with source files from the given `ecosystem`.

        Args:
            * `ecosystem` (ECOSYSTEM): The ecosystem of the desired `SourceCodeDiffer`.

        Returns:
            A `SourceCodeDiffer` for use with source files from the desired ecosystem.

        Raises:
            ValueError: The given `ecosystem` is not supported.
        """
        match ecosystem:
            case ECOSYSTEM.PYPI:
                language = ts_python.language()
            case ECOSYSTEM.NPM:
                language = ts_javascript.language()
            case ECOSYSTEM.GO:
                language = ts_go.language()
            case ECOSYSTEM.GITHUB_ACTION:
                raise ValueError("Diff scans are not available for GitHub Actions")

        return cls(Parser(Language(language)))

    def get_diff(self, left: bytes, right: bytes) -> bytes:
        """
        Generate a minimal, valid program containing all changes between `left` and `right`.

        Args:
            * `left` (bytes): The source code to diff against.
            * `right` (bytes): The source code to be diffed.

        Returns:
            A minimal, syntactically valid program containing all lines in `right` that had
            changes with respect to `left`.

            The returned program is minimal in the sense that it only contains the top-level
            definitions in `right` that had at least one change with respect to `left`.

        Raises:
            ValueError: The inputs could not be correctly parsed by the `SourceCodeDiffer`.
        """
        def node_eq(left: Node, right: Node) -> bool:
            return left.type == right.type and left.text == right.text

        def get_changed_nodes(left: Tree, right: Tree) -> list[Node]:
            return [
                right_node for right_node in right.root_node.children
                if not any(node_eq(right_node, left_node) for left_node in left.root_node.children)
            ]

        def generate_program(nodes: list[Node]) -> bytes:
            return b'\n'.join(right[node.start_byte:node.end_byte] for node in nodes)

        left_tree = self._parser.parse(left)
        right_tree = self._parser.parse(right)

        return generate_program(get_changed_nodes(left_tree, right_tree))


@dataclass
class DirectoryDiff:
    """
    The structured results of recursively diffing two directories.
    """
    left: Path
    right: Path
    added: set[Path]
    changed: set[Path]
    funny: set[Path]

    @classmethod
    def from_directories(cls, left: Path, right: Path) -> Self:
        """
        Recursively diff two directories.

        Args:
            * `left` (Path): The directory to diff against.
            * `right` (Path): The directory to be diffed.

        Returns:
            A `DirectoryDiff` containing the results of diffing the given directories.
        """
        def as_prefixed_paths(prefix: str, names: list[str]) -> set[Path]:
            return set(map(lambda name: Path(prefix) / Path(name), names))

        def inner(acc: tuple[set[Path], set[Path], set[Path]], dcmp) -> tuple[set[Path], set[Path], set[Path]]:
            added = as_prefixed_paths(dcmp.right, dcmp.right_only)
            changed = as_prefixed_paths(dcmp.right, dcmp.diff_files)
            funny = as_prefixed_paths(dcmp.right, dcmp.common_funny)
            return functools.reduce(
                inner,
                dcmp.subdirs.values(),
                (acc[0] | added, acc[1] | changed, acc[2] | funny)
            )

        def as_relative_right(paths: set[Path]) -> set[Path]:
            return set(map(lambda path: path.relative_to(right), paths))

        dcmp = filecmp.dircmp(left, right)
        added, changed, funny = inner((set(), set(), set()), dcmp)

        return cls(
            left,
            right,
            as_relative_right(added),
            as_relative_right(changed),
            as_relative_right(funny)
        )

    def copy_added(self, dst_dir: Path):
        """
        Copy all added files and directories into `dst_dir` while preserving
        the original directory structure.

        Args:
            * `dst_dir` (Path): The directory to copy into.
        """
        self._copy("added", from_right=True, dst_dir=dst_dir)

    def copy_funny_from_right(self, dst_dir: Path):
        """
        Copy all funny files and directories from the right-hand side directory
        into `dst_dir` while preserving the original directory structure.

        Args:
            * `dst_dir` (Path): The directory to copy into.
        """
        self._copy("funny", from_right=True, dst_dir=dst_dir)

    def _copy(self, target: str, from_right: bool, dst_dir: Path):
        src_dir = self.right if from_right else self.left

        targets = None
        match target:
            case "added" if from_right:
                targets = self.added
            case "funny":
                targets = self.funny
        if targets is None:
            log.error("An invalid DirectoryDiff copy operation was attempted")
            sys.exit(1)

        for path in targets:
            src_path = src_dir / path
            dst_path = dst_dir / path
            if src_path.is_dir():
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            elif src_path.is_file():
                os.makedirs(dst_path.parent, exist_ok=True)
                shutil.copy(src_path, dst_path)
            else:
                log.warning(f"Skipping strange path {path} while copying diff items")
