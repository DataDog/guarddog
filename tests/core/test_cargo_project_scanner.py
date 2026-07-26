import os

from click.testing import CliRunner

from guarddog.analyzer.analyzer import Analyzer
from guarddog.cli import cli
from guarddog.ecosystems import LANGUAGE
from guarddog.scanners import CargoLockScanner

CARGO_LOCK = """\
version = 4

[[package]]
name = "local-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "first"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "second"

[[package]]
name = "private-crate"
version = "2.0.0"
source = "registry+https://example.com/index"

[[package]]
name = "git-crate"
version = "3.0.0"
source = "git+https://github.com/example/git-crate"
"""


def test_parse_cargo_lock_includes_only_crates_io_packages():
    scanner = CargoLockScanner()

    dependencies = scanner.parse_requirements(CARGO_LOCK)

    assert [dependency.name for dependency in dependencies] == ["serde"]
    assert {version.version for version in dependencies[0].versions} == {
        "1.0.227",
        "1.0.228",
    }
    assert {version.location for version in dependencies[0].versions} == {8, 14}


def test_find_cargo_lock_files(tmp_path):
    scanner = CargoLockScanner()
    nested = tmp_path / "nested"
    nested.mkdir()
    cargo_lock = nested / "Cargo.lock"
    cargo_lock.write_text(CARGO_LOCK)
    (nested / "cargo.toml").write_text('[package]\nname = "ignored"\n')

    assert scanner.find_requirements(str(tmp_path)) == [str(cargo_lock)]


def test_rust_source_language_and_comment_syntax(tmp_path):
    source = tmp_path / "lib.rs"
    source.write_text("// comment\nlet value = 1;\n/* block\ncomment */\n")

    assert Analyzer._detect_language(str(source)) == LANGUAGE.RUST
    assert Analyzer.is_match_in_comment(str(source), line_number=1)
    assert not Analyzer.is_match_in_comment(str(source), line_number=2)
    assert Analyzer.is_match_in_comment(str(source), line_number=4)


def test_crates_cli_group_is_available():
    result = CliRunner().invoke(cli, ["crates", "--help"])

    assert result.exit_code == 0
    assert "scan" in result.output
    assert "verify" in result.output
