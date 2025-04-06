"""
Provides utilities for diffing directories and source code files.
"""

from dataclasses import dataclass
import filecmp
import functools
from pathlib import Path
from tree_sitter import Language, Node, Parser, Tree
import tree_sitter_go as ts_go
import tree_sitter_javascript as ts_javascript
import tree_sitter_python as ts_python
from typing_extensions import Self

from guarddog.ecosystems import ECOSYSTEM


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

        def select_relevant_nodes(tree: Tree) -> list[Node]:
            relevant_types = {
                "function_definition",
                "class_definition",
                "decorated_definition",
                "expression_statement",
                "import_statement",
                "import_from_statement",
                "assignment",
            }
            return [node for node in tree.root_node.children if node.type in relevant_types]

        def get_changed_nodes(left: Tree, right: Tree) -> list[Node]:
            left_nodes = select_relevant_nodes(left)
            right_nodes = select_relevant_nodes(right)
            return [
                right_node for right_node in right_nodes
                if not any(node_eq(right_node, left_node) for left_node in left_nodes)
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
    added: list[Path]
    changed: list[Path]

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
        def inner(acc: tuple[list[Path], list[Path]], dcmp) -> tuple[list[Path], list[Path]]:
            added = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.right_only))
            changed = list(map(lambda file: Path(dcmp.right) / Path(file), dcmp.diff_files))
            return functools.reduce(inner, dcmp.subdirs.values(), (acc[0] + added, acc[1] + changed))

        dcmp = filecmp.dircmp(left, right)

        added, changed = inner(([], []), dcmp)
        added = list(map(lambda path: path.relative_to(right), added))
        changed = list(map(lambda path: path.relative_to(right), changed))

        return cls(left, right, added, changed)
