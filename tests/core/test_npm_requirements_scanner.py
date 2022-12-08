
from guarddog.scanners.npm_project_scanner import NPMRequirementsScanner


def test_npm_requirements_scanner():
    scanner = NPMRequirementsScanner()
    result = scanner.parse_requirements("""
    {
        "dependencies": {
            "non-existing": "*",
            "express": "4.x"
        }
    }""")
    assert "non-existing" not in result  # ignoring non existing packages
    assert "express" in result
# TODO: handle non-version cases
# TODO: test also the package scanner
