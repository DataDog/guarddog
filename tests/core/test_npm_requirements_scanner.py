import os
import pathlib

import pytest

import guarddog.scanners.npm_project_scanner as npm_project_scanner
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


def test_npm_requirements_scanner_alias():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "this-alias-should-not-be-scanned-directly": "npm:express@4.x"
        }
    }
    """)

    assert "this-alias-should-not-be-scanned-directly" not in result
    lookup = next(filter(lambda r: r.name == "express", result), None)
    assert lookup is not None
    assert len(lookup.versions) > 0


def test_npm_requirements_scanner_scoped_alias():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "this-scoped-alias-should-not-be-scanned-directly": "npm:@types/node@*"
        }
    }
    """)

    assert "this-scoped-alias-should-not-be-scanned-directly" not in result
    lookup = next(filter(lambda r: r.name == "@types/node", result), None)
    assert lookup is not None
    assert len(lookup.versions) > 0


def test_npm_requirements_scanner_excludes_dev_dependencies_by_default(monkeypatch):
    monkeypatch.setattr(
        npm_project_scanner, "NPM_INCLUDE_DEV_DEPENDENCIES", False
    )
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "express": "4.x"
        },
        "devDependencies": {
            "joi": "17.6"
        }
    }
    """)

    dependency_names = {dependency.name for dependency in result}
    assert "express" in dependency_names
    assert "joi" not in dependency_names


def test_npm_requirements_scanner_includes_dev_dependencies_when_enabled(monkeypatch):
    monkeypatch.setattr(
        npm_project_scanner, "NPM_INCLUDE_DEV_DEPENDENCIES", True
    )
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "express": "4.x"
        },
        "devDependencies": {
            "joi": "17.6"
        }
    }
    """)

    dependency_names = {dependency.name for dependency in result}
    assert "express" in dependency_names
    assert "joi" in dependency_names


def test_npm_requirements_scanner_rejects_lockfile():
    """Passing a package-lock.json must fail with a clear error instead of
    silently returning no dependencies (v3) or crashing on dict selectors (v2).
    """
    scanner = NPMRequirementsScanner()

    # lockfile v3 has only a top-level "packages" map, no "dependencies".
    with pytest.raises(ValueError, match="package-lock"):
        scanner.parse_requirements("""
        {
            "name": "proj",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {"name": "proj", "dependencies": {"express": "4.19.2"}},
                "node_modules/express": {"version": "4.19.2"}
            }
        }
        """)

    # lockfile v2 has a top-level "dependencies" map whose values are objects.
    with pytest.raises(ValueError, match="package-lock"):
        scanner.parse_requirements("""
        {
            "name": "proj",
            "lockfileVersion": 2,
            "dependencies": {
                "express": {"version": "4.19.2"}
            }
        }
        """)
