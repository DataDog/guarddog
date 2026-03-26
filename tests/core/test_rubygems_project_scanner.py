import os
import pathlib

from guarddog.scanners import RubyGemsRequirementsScanner


def test_rubygems_parse_requirements():
    scanner = RubyGemsRequirementsScanner()

    with open(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "Gemfile.lock"),
        "r",
    ) as f:
        result = scanner.parse_requirements(f.read())

        expected_gems = [
            ("rake", "13.2.1"),
            ("minitest", "5.25.4"),
        ]

        for name, version in expected_gems:
            lookup = next(
                filter(lambda r: r.name == name, result), None
            )
            assert lookup, f"Expected to find gem {name}"
            versions = {v.version for v in lookup.versions}
            assert version in versions, f"Expected version {version} for {name}"


def test_rubygems_find_requirements():
    scanner = RubyGemsRequirementsScanner()

    requirements = scanner.find_requirements(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources")
    )
    assert len(requirements) == 1
    assert requirements[0].endswith("Gemfile.lock")
