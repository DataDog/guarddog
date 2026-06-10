import os
from unittest.mock import MagicMock, patch

import pytest

from guarddog.sandbox import (
    is_available,
    apply_sandbox,
    _get_common_read_paths,
    _path_variants,
)


class TestIsAvailable:
    @patch("guarddog.sandbox.nono_py", create=True)
    def test_returns_true_when_supported(self, mock_nono):
        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            mock_nono.is_supported.return_value = True
            assert is_available() is True

    @patch("guarddog.sandbox.nono_py", create=True)
    def test_returns_false_when_not_supported(self, mock_nono):
        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            mock_nono.is_supported.return_value = False
            assert is_available() is False


class TestApplySandbox:
    def _make_mock_nono(self):
        mock = MagicMock()
        mock.AccessMode.READ = "READ"
        mock.AccessMode.READ_WRITE = "READ_WRITE"
        mock.is_supported.return_value = True
        return mock

    @patch("guarddog.sandbox._get_common_read_paths", return_value=["/usr"])
    def test_builds_correct_capabilities(self, _mock_paths, tmp_path):
        mock_nono = self._make_mock_nono()

        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            apply_sandbox(
                scan_paths=[str(tmp_path / "pkg")],
                writable_paths=[str(tmp_path / "extract")],
            )

        caps = mock_nono.CapabilitySet.return_value
        caps.block_network.assert_called_once()
        mock_nono.apply.assert_called_once_with(caps)

    @patch("guarddog.sandbox._get_common_read_paths", return_value=["/usr"])
    def test_network_always_blocked(self, _mock_paths, tmp_path):
        mock_nono = self._make_mock_nono()

        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            apply_sandbox(scan_paths=[], writable_paths=[])

        caps = mock_nono.CapabilitySet.return_value
        caps.block_network.assert_called_once()

    def test_common_read_paths_includes_sys_prefix(self):
        import sys

        paths = _get_common_read_paths()
        assert any(p == os.path.realpath(sys.prefix) for p in paths)


class TestPathVariants:
    def test_plain_path_returns_single_entry(self):
        assert _path_variants("/usr") == ["/usr"]

    def test_symlink_returns_both_link_and_target(self, tmp_path):
        """Both the symlink path and its target must be granted: the import
        machinery walks sys.path via the symlink (e.g. cpython-3.12 ->
        cpython-3.12.8), so granting only the realpath breaks lazy imports."""
        target = tmp_path / "cpython-3.12.8"
        target.mkdir()
        link = tmp_path / "cpython-3.12"
        link.symlink_to(target)

        variants = _path_variants(str(link))

        assert str(link) in variants
        assert str(target) in variants

    def test_symlinked_stdlib_dir_is_granted_via_both_paths(self, tmp_path):
        """A managed-interpreter layout where the stdlib lives behind a
        versioned symlink must yield read access through the symlink path."""
        real_lib = tmp_path / "cpython-3.12.8" / "lib"
        real_lib.mkdir(parents=True)
        link = tmp_path / "cpython-3.12"
        link.symlink_to(tmp_path / "cpython-3.12.8")
        symlinked_lib = link / "lib"

        variants = _path_variants(str(symlinked_lib))

        assert str(symlinked_lib) in variants
        assert str(real_lib) in variants


class TestScanCLISandboxFlag:
    @patch("guarddog.cli.get_package_scanner")
    @patch("guarddog.cli.sandbox_available", return_value=False)
    def test_exits_when_sandbox_forced_but_unavailable(
        self, _mock_avail, _mock_scanner
    ):
        """--sandbox flag should hard-fail when sandbox is not available"""
        from click.testing import CliRunner
        from guarddog.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["pypi", "scan", "some-package", "--sandbox"])
        assert result.exit_code != 0

    @patch("guarddog.cli.get_package_scanner")
    def test_no_sandbox_skips_check(self, mock_get_scanner):
        from click.testing import CliRunner
        from guarddog.cli import cli

        mock_scanner = MagicMock()
        mock_scanner.scan_remote.return_value = {
            "issues": 0,
            "errors": {},
            "results": {},
            "risk_score": {},
            "risks": [],
            "path": "/tmp/x",
        }
        mock_get_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(cli, ["pypi", "scan", "some-package", "--no-sandbox"])
        assert "not supported" not in (result.output or "").lower()
