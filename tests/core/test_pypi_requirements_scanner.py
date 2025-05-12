import os
import pathlib

from guarddog.scanners.pypi_project_scanner import PypiRequirementsScanner


# Regression test for https://github.com/DataDog/guarddog/issues/78
def test_requirements_scanner():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(["not-a-real-package==1.0.0", "flask==2.2.2"])
    )
    assert "not-a-real-package" not in result

    for p, v in [("flask", "2.2.2")]:
        lookup = next(
            filter(lambda r: r.name == p, result), None
        )
        assert lookup
        assert v in lookup.versions


def test_pypi_find_requirements():
    scanner = PypiRequirementsScanner()


    requirements = scanner.find_requirements(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources")
    )
    assert requirements == [os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "requirements.txt")]

# Regression test for https://github.com/DataDog/guarddog/issues/88
def test_requirements_scanner_on_git_url_packages():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(
            [
                "flask==2.2.2",
                "https://wxpython.org/Phoenix/snapshot-builds/wxPython_Phoenix-3.0.3.dev1820+49a8884-cp34-none-win_amd64.whl",
                "guarddog @ git+https://github.com/DataDog/guarddog.git",
                "git+https://github.com/DataDog/guarddog.git",
            ]
        )
    )
    lookup = next(
        filter(lambda r: r.name == "guarddog", result), None
    )
    assert lookup is not None
    assert "git+https://github.com/DataDog/guarddog.git" in [v.version for v in lookup.versions]
    assert "flask" in result
    assert len(result) == 2
