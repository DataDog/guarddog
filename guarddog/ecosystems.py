from enum import Enum


class ECOSYSTEM(Enum):
    PYPI = "pypi"
    NPM = "npm"
    GO = "go"
    GITHUB_ACTION = "github-action"


# TODO(ikretz): Get rid of this function
def get_friendly_name(ecosystem: ECOSYSTEM) -> str:
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return "PyPI"
        case ECOSYSTEM.NPM:
            return "npm"
        case ECOSYSTEM.GO:
            return "go"
        case ECOSYSTEM.GITHUB_ACTION:
            return "GitHub Action"
        case _:
            return ecosystem.value
