import os
import pathlib

from guarddog.scanners.npm_project_scanner import NPMRequirementsScanner


def test_npm_requirements_scanner():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "non-existing": "*",
            "express": "4.x"
        }
    }
    """)
    assert "non-existing" not in result  # ignoring non existing packages
    assert "express" in result


def test_npm_find_requirements():
    scanner = NPMRequirementsScanner()


    requirements = scanner.find_requirements(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources")
    )
    assert requirements == [os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "package.json")]


def test_npm_requirements_scanner_github():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "express": "expressjs/express",
            "cors": "https://github.com/expressjs/cors.git"
        }
    }
    """)
    assert "express" in result
    assert "expressjs/express" in result["express"]
    assert "cors" in result
    assert "https://github.com/expressjs/cors.git" in result["cors"]
