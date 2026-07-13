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
        lookup = next(filter(lambda r: r.name == p, result), None)
        assert lookup
        assert v in lookup.versions


def test_pypi_find_requirements():
    scanner = PypiRequirementsScanner()

    resources = str(os.path.join(pathlib.Path(__file__).parent.resolve(), "resources"))
    requirements = scanner.find_requirements(resources)
    assert sorted(requirements) == sorted(
        [
            os.path.join(resources, "requirements.txt"),
            os.path.join(resources, "pyproject.toml"),
            os.path.join(resources, "poetry.lock"),
        ]
    )


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
                "requests",
            ]
        )
    )
    lookup = next(filter(lambda r: r.name == "guarddog", result), None)
    assert lookup is not None
    assert "git+https://github.com/DataDog/guarddog.git" in [
        v.version for v in lookup.versions
    ]
    assert "flask" in result
    assert len(result) == 3
    lookup = next(filter(lambda r: r.name == "requests", result), None)
    assert lookup is not None
    assert len(lookup.versions) == 1


# Tests for https://github.com/DataDog/guarddog/issues/781


def test_parse_pyproject_pep621():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(
            [
                "[project]",
                'name = "sample-project"',
                'dependencies = ["flask==2.2.2", "not-a-real-package==1.0.0"]',
                "",
                "[project.optional-dependencies]",
                'dev = ["requests"]',
            ]
        )
    )
    assert "not-a-real-package" not in result
    flask = next(filter(lambda r: r.name == "flask", result), None)
    assert flask
    assert "2.2.2" in flask.versions
    assert next(filter(lambda r: r.name == "requests", result), None) is not None


def test_parse_pyproject_poetry():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(
            [
                "[tool.poetry]",
                'name = "sample-project"',
                "",
                "[tool.poetry.dependencies]",
                'python = ">=3.10,<4"',
                'flask = "2.2.2"',
                'weird-git-dep = { git = "https://example.com/repo.git" }',
                "",
                "[tool.poetry.group.dev.dependencies]",
                'requests = "*"',
            ]
        )
    )
    # the python constraint and git dependencies must not be treated as PyPI packages
    assert "python" not in result
    assert "weird-git-dep" not in result
    flask = next(filter(lambda r: r.name == "flask", result), None)
    assert flask
    assert "2.2.2" in flask.versions
    assert next(filter(lambda r: r.name == "requests", result), None) is not None


def test_parse_pyproject_poetry_caret_constraint():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(
            [
                "[tool.poetry.dependencies]",
                'flask = "^2.2"',
            ]
        )
    )
    flask = next(filter(lambda r: r.name == "flask", result), None)
    assert flask
    # every resolved version must respect the caret range >=2.2,<3
    for v in flask.versions:
        assert v.version.startswith("2.")


def test_poetry_constraint_to_pep440():
    convert = PypiRequirementsScanner._poetry_constraint_to_pep440
    assert convert("*") == ""
    assert convert("2.2.2") == "==2.2.2"
    assert convert("^1.2.3") == ">=1.2.3,<2"
    assert convert("^0.2.3") == ">=0.2.3,<0.3"
    assert convert("^0.0.3") == ">=0.0.3,<0.0.4"
    assert convert("~1.2.3") == ">=1.2.3,<1.3"
    assert convert("~1") == ">=1,<2"
    assert convert(">=1.2,<2") == ">=1.2,<2"
    assert convert("~=1.2") == "~=1.2"


def test_parse_poetry_lockfile():
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements(
        "\n".join(
            [
                "[[package]]",
                'name = "flask"',
                'version = "2.2.2"',
                "",
                "[[package]]",
                'name = "not-a-real-package"',
                'version = "1.0.0"',
                "",
                "[metadata]",
                'lock-version = "2.0"',
            ]
        )
    )
    assert "not-a-real-package" not in result
    flask = next(filter(lambda r: r.name == "flask", result), None)
    assert flask
    assert "2.2.2" in flask.versions


def test_parse_requirements_garbage_input_returns_empty():
    # a package.json fed to the pypi scanner must not crash and yields nothing
    scanner = PypiRequirementsScanner()
    result = scanner.parse_requirements('{"dependencies": {"express": "4.x"}}')
    assert result == []
