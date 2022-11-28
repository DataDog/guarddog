from guarddog.scanners.project_scanner import RequirementsScanner


# Regression test for https://github.com/DataDog/guarddog/issues/78
def test_requirements_scanner_on_non_existing_package():
    scanner = RequirementsScanner()
    result = scanner.parse_requirements(["not-a-real-package==1.0.0"])
    assert "not-a-real-package" not in result
