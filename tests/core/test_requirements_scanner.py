import pkg_resources

from guarddog.scanners.project_scanner import RequirementsScanner


# Regression test for https://github.com/DataDog/guarddog/issues/78
def test_requirements_scanner():
    scanner = RequirementsScanner()
    result = scanner.parse_requirements(["not-a-real-package==1.0.0", "flask==2.2.2"])
    assert "not-a-real-package" not in result  # ignoring non existing packages
    assert "flask" in result


# Regression test for https://github.com/DataDog/guarddog/issues/88
def test_requirements_scanner_on_git_url_packages():
    scanner = RequirementsScanner()
    result = scanner.parse_requirements([
        "flask==2.2.2",
        "http://wxpython.org/Phoenix/snapshot-builds/wxPython_Phoenix-3.0.3.dev1820+49a8884-cp34-none-win_amd64.whl",
        "guarddog @ git+https://github.com/DataDog/guarddog.git",
        "git+https://github.com/DataDog/guarddog.git"
    ])
    assert "guarddog" in result
    assert "flask" in result
    assert len(result) == 2

