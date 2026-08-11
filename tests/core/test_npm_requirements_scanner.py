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


def test_npm_requirements_scanner_exclude_dev_omits_dev_deps():
    """When exclude_dev=True, devDependencies must not appear in the output."""
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements(
        """
    {
        "dependencies": {
            "express": "4.x"
        },
        "devDependencies": {
            "jest": "^29.0.0",
            "typescript": "^5.0.0"
        }
    }
    """,
        exclude_dev=True,
    )
    names = [d.name for d in result]
    assert "express" in names, "production dependency must be included"
    assert "jest" not in names, "jest is a devDependency and must be excluded"
    assert "typescript" not in names, "typescript is a devDependency and must be excluded"


def test_npm_requirements_scanner_include_dev_by_default():
    """Default behavior (exclude_dev=False) must include devDependencies."""
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements(
        """
    {
        "dependencies": {
            "cors": "*"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }
    """
    )
    names = [d.name for d in result]
    assert "cors" in names
    assert "jest" in names, "devDependency must be present when exclude_dev is not set"


def test_npm_requirements_scanner_exclude_dev_no_prod_deps():
    """exclude_dev=True with only devDependencies and no dependencies key returns no deps."""
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements(
        """
    {
        "devDependencies": {
            "jest": "^29.0.0"
        }
    }
    """,
        exclude_dev=True,
    )
    assert result == [], "no production dependencies → empty list"


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
