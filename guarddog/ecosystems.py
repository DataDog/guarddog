from enum import Enum


class ECOSYSTEM(Enum):
    PYPI = "pypi"
    NPM = "npm"
    GO = "go"
    GITHUB_ACTION = "github-action"
    EXTENSION = "extension"
    RUBYGEMS = "rubygems"


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
        case ECOSYSTEM.EXTENSION:
            return "Extension"
        case ECOSYSTEM.RUBYGEMS:
            return "RubyGems"
        case _:
            return ecosystem.value
