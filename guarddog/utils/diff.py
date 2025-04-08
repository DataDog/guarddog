"""
Provides utilities for diffing directories and source code files.
"""

from dataclasses import dataclass
import filecmp
import functools
import logging
from pathlib import Path
from typing_extensions import Self

from tree_sitter import Language, Node, Parser
import tree_sitter_go as ts_go
import tree_sitter_javascript as ts_javascript
import tree_sitter_python as ts_python

from guarddog.ecosystems import ECOSYSTEM

log = logging.getLogger("guarddog")

# The TreeSitter.Node types of import-like statements in each supported language
PYTHON_IMPORT_TYPES = {
    "aliased_import",
    "future_import_statement",
    "import_from_statement",
    "import_statement",
}
NPM_IMPORT_TYPES = {
    "import_statement",
    "namespace_import",
    "require_call",
}
GO_IMPORT_TYPES = {
    "import_declaration"
}


class SourceCodeDiffer:
    """
    Provides source code diffing utilities parameterized over target language.
    """
    def __init__(self, parser: Parser, import_types: set[str]):
        self._parser = parser
        self._import_types = import_types

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
                language, import_types = ts_python.language(), PYTHON_IMPORT_TYPES
            case ECOSYSTEM.NPM:
                language, import_types = ts_javascript.language(), NPM_IMPORT_TYPES
            case ECOSYSTEM.GO:
                language, import_types = ts_go.language(), GO_IMPORT_TYPES
            case ECOSYSTEM.GITHUB_ACTION:
                raise ValueError("Diff scans are not available for GitHub Actions")

        return cls(Parser(Language(language)), import_types)

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

        def generate_program(nodes: list[Node]) -> bytes:
            program = bytearray()
            line, column = 0, 0

            for node in nodes:
                while line < node.start_point[0]:
                    program.extend(b'\n')
                    line += 1
                while column < node.start_point[1]:
                    program.extend(b' ')
                    column += 1
                if node.text:
                    program.extend(node.text)
                line, column = node.end_point[0], node.end_point[1]

            return bytes(program)

        left_tree = self._parser.parse(left)
        right_tree = self._parser.parse(right)

        relevant_nodes = [
            right_node for right_node in right_tree.root_node.children
            if (
                right_node.type in self._import_types
                or not any(node_eq(right_node, left_node) for left_node in left_tree.root_node.children)
            )
        ]
        has_relevant_change = any(node.type not in self._import_types for node in relevant_nodes)

        return generate_program(relevant_nodes) if has_relevant_change else bytes()


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
