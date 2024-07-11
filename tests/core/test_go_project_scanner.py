import os
import pathlib

from guarddog.scanners import GoDependenciesScanner


def test_go_parse_requirements():
    scanner = GoDependenciesScanner()

    with open(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "go.mod"),
        "r",
    ) as f:
        requirements = scanner.parse_requirements(f.read())
        assert requirements == {
            "go.uber.org/multierr": {"v1.11.0"},
            "go.uber.org/zap": {"v1.27.0"},
        }
