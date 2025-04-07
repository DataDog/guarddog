"""
Tests for directory and source code diffing utilities.
"""

from pathlib import Path
import pytest

from guarddog.ecosystems import ECOSYSTEM
from guarddog.utils.diff import SourceCodeDiffer

INPUTS_PATH = Path(__file__).parent.resolve() / "resources" / "diff"


@pytest.mark.parametrize(
        "ecosystem,test_name",
        [
            (ECOSYSTEM.PYPI, "function"),
            (ECOSYSTEM.PYPI, "class"),
            (ECOSYSTEM.NPM, "function"),
            (ECOSYSTEM.NPM, "class"),
            (ECOSYSTEM.GO, "function"),
            (ECOSYSTEM.GO, "struct"),
        ]
)
def test_source_code_diff(ecosystem: ECOSYSTEM, test_name: str):
    ecosystem_str, extension = _fixes_for_ecosystem(ecosystem)
    left, right, diff = (name + extension for name in ("left", "right", "diff"))

    with open(INPUTS_PATH / ecosystem_str / test_name / left, 'rb') as r:
        left = r.read()
    with open(INPUTS_PATH / ecosystem_str / test_name / right, 'rb') as r:
        right = r.read()
    with open(INPUTS_PATH / ecosystem_str / test_name / diff, 'rb') as r:
        diff = r.read()

    result = SourceCodeDiffer.from_ecosystem(ecosystem).get_diff(left, right)

    assert diff[-1:] == b'\n' and diff[:-1] == result


@pytest.mark.parametrize(
        "ecosystem,test_name",
        [
            (ECOSYSTEM.PYPI, "function"),
            (ECOSYSTEM.PYPI, "class"),
            (ECOSYSTEM.NPM, "function"),
            (ECOSYSTEM.NPM, "class"),
            (ECOSYSTEM.GO, "function"),
            (ECOSYSTEM.GO, "struct"),
        ]
)
def test_source_code_diff_no_change(ecosystem: ECOSYSTEM, test_name):
    ecosystem_str, extension = _fixes_for_ecosystem(ecosystem)
    target = "left" + extension

    with open(INPUTS_PATH / ecosystem_str / test_name / target, 'rb') as r:
        target = r.read()

    result = SourceCodeDiffer.from_ecosystem(ecosystem).get_diff(target, target)

    assert not result

def _fixes_for_ecosystem(ecosystem: ECOSYSTEM) -> tuple[str, str]:
    # TODO(ikretz): Replace with `__str__` implementation for `ECOSYSTEM`
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return "pypi", ".py"
        case ECOSYSTEM.NPM:
            return "npm", ".js"
        case ECOSYSTEM.GO:
            return "go", ".go"
        case ECOSYSTEM.GITHUB_ACTION:
            raise AssertionError("Source code diffing is not implemented for GitHub Actions")
