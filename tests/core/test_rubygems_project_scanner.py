import os
import pathlib
import textwrap

from guarddog.scanners import RubyGemsRequirementsScanner

SAMPLE_GEMFILE_LOCK = textwrap.dedent("""\
    GEM
      remote: https://rubygems.org/
      specs:
        rake (13.2.1)
        minitest (5.25.4)

    PLATFORMS
      ruby

    DEPENDENCIES
      minitest (~> 5.25)
      rake (~> 13.2)

    BUNDLED WITH
       2.6.2
""")


def test_rubygems_parse_requirements():
    scanner = RubyGemsRequirementsScanner()
    result = scanner.parse_requirements(SAMPLE_GEMFILE_LOCK)

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
    assert "Gemfile.lock" not in [os.path.basename(r) for r in requirements]
