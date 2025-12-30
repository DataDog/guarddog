import os
import pathlib

from guarddog.scanners import GoDependenciesScanner


def test_go_parse_requirements():
    scanner = GoDependenciesScanner()

    with open(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "go.mod"),
        "r",
    ) as f:
        result = scanner.parse_requirements(f.read())

        for p, v in [
            ("go.uber.org/multierr", "v1.11.0"),
            ("go.uber.org/zap", "v1.27.0"),
        ]:
            lookup = next(filter(lambda r: r.name == p, result), None)
            assert lookup
            assert v in lookup.versions


def test_go_find_requirements():
    scanner = GoDependenciesScanner()

    requirements = scanner.find_requirements(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources")
    )
    assert requirements == [
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "go.mod")
    ]
