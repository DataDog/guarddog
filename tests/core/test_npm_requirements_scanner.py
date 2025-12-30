import os
import pathlib

from guarddog.scanners.npm_project_scanner import NPMRequirementsScanner


def test_npm_requirements_scanner():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements(
        """
    {
        "dependencies": {
            "non-existing": "*",
            "express": "4.x",
            "cors": "*"
        }
    }
    """
    )
    assert "non-existing" not in result  # ignoring non existing packages
    assert "express" in result
    lookup = next(filter(lambda r: r.name == "cors", result), None)
    assert lookup is not None
    assert len(lookup.versions) == 1


def test_npm_find_requirements():
    scanner = NPMRequirementsScanner()

    requirements = scanner.find_requirements(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources")
    )
    assert requirements == [
        os.path.join(
            pathlib.Path(__file__).parent.resolve(), "resources", "package.json"
        )
    ]


def test_npm_requirements_scanner_github():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements(
        """
    {
        "dependencies": {
            "express": "expressjs/express",
            "cors": "https://github.com/expressjs/cors.git"
        }
    }
    """
    )
    lookup = next(filter(lambda r: r.name == "express", result), None)
    assert lookup is not None
    assert "expressjs/express" in lookup.versions

    lookup = next(filter(lambda r: r.name == "cors", result), None)
    assert lookup is not None
    assert "https://github.com/expressjs/cors.git" in lookup.versions
