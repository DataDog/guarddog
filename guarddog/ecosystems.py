from enum import Enum


class ECOSYSTEM(Enum):
    PYPI = "pypi"
    NPM = "npm"


def get_friendly_name(ecosystem: ECOSYSTEM) -> str:
    match ecosystem:
        case ECOSYSTEM.PYPI:
            return "PyPI"
        case ECOSYSTEM.NPM:
            return "npm"
        case _:
            return ecosystem.value
