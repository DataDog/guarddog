import unittest
import unittest.mock as mock
import zipfile

import tarsafe

import guarddog.cli
from guarddog.ecosystems import ECOSYSTEM
import guarddog.scanners.scanner as scanner


class TestCli(unittest.TestCase):

    def test_local_directory(self):
        """
        Test that the CLI identifies local directories correctly
        """
        self._test_local_directory_template("/tmp/foo")
        self._test_local_directory_template("./foo")
        self._test_local_directory_template("../foo")
        self._test_local_directory_template(".")

    def test_local_file(self):
        """
        Test that the CLI identifies local files correctly
        """
        self._test_local_file_template("/tmp/foo")
        self._test_local_file_template("./foo")
        self._test_local_file_template("../foo")

    def test_get_rule_param_include(self):
        """
        Test the parsing function returns the included parameter
        """
        rules = guarddog.cli._get_rule_param(("shady-links",), (), ECOSYSTEM.NPM)
        assert rules
        assert len(rules) == 1

    def test_get_rule_param_exclude(self):
        """
        Test the parsing function returns a list without the excluded parameter
        """
        rules = guarddog.cli._get_rule_param((), ("shady-links",), ECOSYSTEM.PYPI)
        assert rules
        assert len(rules) != 1
        assert "shady-links" not in rules

    def test_get_rule_param_empty(self):
        """
        Test the parsing function returns None when no rules are provided
        """
        rules = guarddog.cli._get_rule_param((), (), ECOSYSTEM.PYPI)
        assert rules is None

    def test_add_pypi_inspector_url_for_pypi_scan_with_findings(self):
        results = {"issues": 1, "package_version": "2.28.1"}
        guarddog.cli._add_pypi_inspector_url(results, "requests", ECOSYSTEM.PYPI)
        assert (
            results["pypi_inspector_url"]
            == "https://inspector.pypi.io/project/requests/2.28.1/"
        )

    def test_add_pypi_inspector_url_escapes_package_and_version(self):
        results = {"issues": 1, "package_version": "1.0.0+local"}
        guarddog.cli._add_pypi_inspector_url(results, "my package", ECOSYSTEM.PYPI)
        assert (
            results["pypi_inspector_url"]
            == "https://inspector.pypi.io/project/my%20package/1.0.0%2Blocal/"
        )

    def test_add_pypi_inspector_url_skips_non_matching_scans(self):
        results = {"issues": 0, "package_version": "2.28.1"}
        guarddog.cli._add_pypi_inspector_url(results, "requests", ECOSYSTEM.PYPI)
        assert "pypi_inspector_url" not in results

        results = {"issues": 1, "package_version": "1.0.0"}
        guarddog.cli._add_pypi_inspector_url(results, "lodash", ECOSYSTEM.NPM)
        assert "pypi_inspector_url" not in results

    def _test_local_directory_template(self, directory: str):
        # `directory` is a directory
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch("os.listdir") as listdir:
                listdir.return_value = []
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan(
                        directory,
                        "0.1.0",
                        (),
                        (),
                        None,
                        False,
                        ECOSYSTEM.PYPI,
                        sandbox=False,
                    )
                self.assertIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a local directory",
                    cm.output,
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a local archive file",
                    cm.output,
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a remote target",
                    cm.output,
                )

        # `directory` is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(
                    scanner.PackageScanner, "scan_local", return_value={}
                ) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan(
                            directory,
                            "0.1.0",
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.PYPI,
                            sandbox=False,
                        )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a local directory",
                        cm.output,
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a local archive file",
                        cm.output,
                    )
                    self.assertIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a remote target",
                        cm.output,
                    )

    def test_remote_url(self):
        """Test that the CLI identifies remote archive URLs correctly"""
        self._test_remote_url_template("https://example.com/package.whl")
        self._test_remote_url_template("http://example.com/package.tar.gz")

    def test_remote_url_rejects_version(self):
        """Test that --version is rejected for remote archive URL scans"""
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with self.assertRaises(SystemExit):
                    guarddog.cli._scan(
                        "https://example.com/package.whl",
                        "1.0.0",
                        (),
                        (),
                        None,
                        False,
                        ECOSYSTEM.PYPI,
                        sandbox=False,
                    )

    def _test_remote_url_template(self, url: str):
        mock_response = mock.MagicMock()
        mock_response.raw.read.return_value = b""

        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with mock.patch(
                    "guarddog.cli.requests.get", return_value=mock_response
                ):
                    with mock.patch("guarddog.cli.safe_extract"):
                        with mock.patch.object(
                            scanner.PackageScanner, "scan_local", return_value={}
                        ):
                            with self.assertLogs("guarddog", level="DEBUG") as cm:
                                guarddog.cli._scan(
                                    url,
                                    None,
                                    (),
                                    (),
                                    None,
                                    False,
                                    ECOSYSTEM.PYPI,
                                    sandbox=False,
                                )
                            self.assertIn(
                                f"DEBUG:guarddog:Considering that '{url}' is a remote archive URL",
                                cm.output,
                            )
                            self.assertNotIn(
                                f"DEBUG:guarddog:Considering that '{url}' is a remote target",
                                cm.output,
                            )

    def test_s3_url(self):
        """Test that the CLI routes s3:// targets through the S3 branch"""
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with mock.patch(
                    "guarddog.utils.s3.verify_aws_authentication"
                ) as verify:
                    with mock.patch(
                        "guarddog.utils.s3.download_from_s3",
                        return_value=("folder", "/tmp/synced"),
                    ) as download:
                        with mock.patch.object(
                            scanner.PackageScanner, "scan_local", return_value={}
                        ) as scan_local:
                            with self.assertLogs("guarddog", level="DEBUG") as cm:
                                guarddog.cli._scan(
                                    "s3://bucket/path/to/pkg",
                                    None,
                                    (),
                                    (),
                                    None,
                                    False,
                                    ECOSYSTEM.NPM,
                                    sandbox=False,
                                )
                            self.assertIn(
                                "DEBUG:guarddog:Considering that "
                                "'s3://bucket/path/to/pkg' is an S3 path",
                                cm.output,
                            )
                            verify.assert_called_once()
                            download.assert_called_once()
                            scan_local.assert_called_once()
                            self.assertEqual(
                                scan_local.call_args.args[0], "/tmp/synced"
                            )

    def test_s3_url_auth_failure_exits(self):
        """Test that a failed AWS auth check exits non-zero for S3 scans"""
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with mock.patch(
                    "guarddog.utils.s3.verify_aws_authentication",
                    side_effect=RuntimeError("no AWS credentials found"),
                ):
                    with self.assertRaises(SystemExit):
                        guarddog.cli._scan(
                            "s3://bucket/path/to/pkg",
                            None,
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.NPM,
                            sandbox=False,
                        )

    def test_s3_url_rejects_version(self):
        """Test that --version is rejected for S3 scans"""
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with self.assertRaises(SystemExit):
                    guarddog.cli._scan(
                        "s3://bucket/path/to/pkg",
                        "1.0.0",
                        (),
                        (),
                        None,
                        False,
                        ECOSYSTEM.NPM,
                        sandbox=False,
                    )

    def test_s3_archive_object_is_extracted(self):
        """A single archive object from S3 is extracted before scanning"""
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with mock.patch("guarddog.utils.s3.verify_aws_authentication"):
                    with mock.patch(
                        "guarddog.utils.s3.download_from_s3",
                        return_value=("archive", "/tmp/dl/pkg.tgz"),
                    ):
                        with mock.patch("guarddog.cli.safe_extract") as safe_extract:
                            with mock.patch.object(
                                scanner.PackageScanner, "scan_local", return_value={}
                            ) as scan_local:
                                guarddog.cli._scan(
                                    "s3://bucket/path/pkg.tgz",
                                    None,
                                    (),
                                    (),
                                    None,
                                    False,
                                    ECOSYSTEM.NPM,
                                    sandbox=False,
                                )
                            safe_extract.assert_called_once()
                            scan_local.assert_called_once()
                            # Scans the extracted dir, not the raw archive.
                            self.assertTrue(
                                scan_local.call_args.args[0].endswith("_extracted")
                            )

    def test_s3_sync_runs_before_sandbox(self):
        """The S3 sync (needs network) must run before the sandbox is applied"""
        order = []
        with mock.patch("os.path.isdir", return_value=False):
            with mock.patch("os.path.isfile", return_value=False):
                with mock.patch("guarddog.cli.sandbox_available", return_value=True):
                    with mock.patch("guarddog.utils.s3.verify_aws_authentication"):
                        with mock.patch(
                            "guarddog.utils.s3.download_from_s3",
                            side_effect=lambda *a, **k: (
                                order.append("download") or ("folder", "/tmp/synced")
                            ),
                        ):
                            with mock.patch(
                                "guarddog.cli.apply_sandbox",
                                side_effect=lambda *a, **k: order.append("sandbox"),
                            ):
                                with mock.patch.object(
                                    scanner.PackageScanner,
                                    "scan_local",
                                    return_value={},
                                ):
                                    guarddog.cli._scan(
                                        "s3://bucket/path/pkg",
                                        None,
                                        (),
                                        (),
                                        None,
                                        False,
                                        ECOSYSTEM.NPM,
                                        sandbox=True,
                                    )
        self.assertEqual(order, ["download", "sandbox"])

    def _test_local_file_template(self, filename: str):
        # `filename` is a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = True
                # The next two patches are to make sure we don't try
                # to extract the test filename
                with mock.patch("tarsafe.is_tarfile") as is_tar:
                    is_tar.return_value = False
                    with mock.patch("zipfile.is_zipfile") as is_zip:
                        is_zip.return_value = False
                        with mock.patch.object(
                            scanner.PackageScanner, "scan_local", return_value={}
                        ) as _:
                            try:
                                with self.assertLogs("guarddog", level="DEBUG") as cm:
                                    guarddog.cli._scan(
                                        filename,
                                        "0.1.0",
                                        (),
                                        (),
                                        None,
                                        False,
                                        ECOSYSTEM.PYPI,
                                        sandbox=False,
                                    )
                            # Since is_tar_archive and is_zip_archive have been
                            # patched accordingly, we always end up here
                            except SystemExit:
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a local directory",
                                    cm.output,
                                )
                                self.assertIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a local archive file",
                                    cm.output,
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a remote target",
                                    cm.output,
                                )

        # `filename` is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(
                    scanner.PackageScanner, "scan_local", return_value={}
                ) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan(
                            filename,
                            "0.1.0",
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.PYPI,
                            sandbox=False,
                        )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a local directory",
                        cm.output,
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a local archive file",
                        cm.output,
                    )
                    self.assertIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a remote target",
                        cm.output,
                    )

    def test_fails_when_sandbox_unavailable_by_default(self):
        """With no sandbox flag, an unavailable sandbox must abort the scan."""
        with mock.patch("guarddog.cli.sandbox_available", return_value=False):
            with mock.patch("os.path.isdir", return_value=True):
                with mock.patch.object(
                    scanner.PackageScanner, "scan_local", return_value={}
                ) as scan_local:
                    with self.assertRaises(SystemExit):
                        guarddog.cli._scan(
                            "/tmp/foo",
                            None,
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.PYPI,
                            sandbox=None,
                        )
                    scan_local.assert_not_called()

    def test_fails_when_sandbox_forced_but_unavailable(self):
        """--sandbox with no available sandbox must abort the scan."""
        with mock.patch("guarddog.cli.sandbox_available", return_value=False):
            with mock.patch("os.path.isdir", return_value=True):
                with mock.patch.object(
                    scanner.PackageScanner, "scan_local", return_value={}
                ) as scan_local:
                    with self.assertRaises(SystemExit):
                        guarddog.cli._scan(
                            "/tmp/foo",
                            None,
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.PYPI,
                            sandbox=True,
                        )
                    scan_local.assert_not_called()

    def test_no_sandbox_flag_scans_when_sandbox_unavailable(self):
        """--no-sandbox must let the scan proceed even without a sandbox."""
        with mock.patch("guarddog.cli.sandbox_available", return_value=False):
            with mock.patch("guarddog.cli.apply_sandbox") as apply_sandbox:
                with mock.patch("os.path.isdir", return_value=True):
                    with mock.patch.object(
                        scanner.PackageScanner, "scan_local", return_value={}
                    ) as scan_local:
                        guarddog.cli._scan(
                            "/tmp/foo",
                            None,
                            (),
                            (),
                            None,
                            False,
                            ECOSYSTEM.PYPI,
                            sandbox=False,
                        )
                        scan_local.assert_called_once()
                        apply_sandbox.assert_not_called()


if __name__ == "__main__":
    unittest.main()
