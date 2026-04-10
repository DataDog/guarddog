from unittest.mock import MagicMock, patch, call
import pytest

from guarddog.sandbox import is_available, apply_sandbox, _get_common_read_paths


class TestIsAvailable:
    @patch("guarddog.sandbox.nono_py", create=True)
    def test_returns_true_when_supported(self, mock_nono):
        # Patch the import inside is_available
        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            mock_nono.is_supported.return_value = True
            assert is_available() is True

    @patch.dict("sys.modules", {"nono_py": None})
    def test_returns_false_when_import_fails(self):
        assert is_available() is False

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

        ctx = MagicMock()
        ctx.query_path.return_value = {"status": "allowed"}
        mock.QueryContext.return_value = ctx
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
    def test_raises_on_query_denial(self, _mock_paths, tmp_path):
        mock_nono = self._make_mock_nono()
        ctx = mock_nono.QueryContext.return_value
        ctx.query_path.return_value = {"status": "denied"}

        with patch.dict("sys.modules", {"nono_py": mock_nono}):
            with pytest.raises(RuntimeError, match="Sandbox validation failed"):
                apply_sandbox(
                    scan_paths=[],
                    writable_paths=[str(tmp_path / "extract")],
                )

        mock_nono.apply.assert_not_called()

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


class TestScanCLISandboxFlag:
    @patch("guarddog.cli.get_package_scanner")
    @patch("guarddog.sandbox.is_available", return_value=False)
    def test_exits_when_sandbox_unavailable(self, _mock_avail, _mock_scanner):
        from click.testing import CliRunner
        from guarddog.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["pypi", "scan", "some-package"])
        assert result.exit_code != 0
        assert "not supported" in result.output.lower() or "sandbox" in result.output.lower()

    @patch("guarddog.cli.get_package_scanner")
    def test_no_sandbox_skips_check(self, mock_get_scanner):
        from click.testing import CliRunner
        from guarddog.cli import cli

        mock_scanner = MagicMock()
        mock_scanner.scan_remote.return_value = {
            "issues": 0, "errors": {}, "results": {},
            "risk_score": {}, "risks": [], "path": "/tmp/x",
        }
        mock_get_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(cli, ["pypi", "scan", "some-package", "--no-sandbox"])
        # Should not exit with sandbox error
        assert "not supported" not in (result.output or "").lower()


import os
