import unittest
import unittest.mock as mock

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

    def test_scan_diff(self):
        """
        Test that the CLI identifies diff scans correctly
        """
        identifier, diff = "foo", "bar"

        # Targets are both local directories
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch.object(scanner.PackageScanner, 'scan_diff_local', return_value={}) as _:
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan(identifier, None, diff, (), (), None, False, ECOSYSTEM.PYPI)
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{identifier}' is a local scan target",
                    cm.output
                )
                self.assertIn(
                    f"DEBUG:guarddog:Considering that '{identifier}' is a local diff scan target",
                    cm.output
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{identifier}' is a remote scan target",
                    cm.output
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{identifier}' is a remote diff scan target",
                    cm.output
                )

        # Targets are both local archive files
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = True
                # The next two patches are to make sure we don't try to extract the test files
                with mock.patch("tarsafe.is_tarfile") as is_tar:
                    is_tar.return_value = False
                    with mock.patch("zipfile.is_zipfile") as is_zip:
                        is_zip.return_value = False
                        with mock.patch.object(scanner.PackageScanner, 'scan_diff_local', return_value={}) as _:
                            try:
                                with self.assertLogs("guarddog", level="DEBUG") as cm:
                                    guarddog.cli._scan(identifier, None, diff, (), (), None, False, ECOSYSTEM.PYPI)
                            # Since is_tar_archive and is_zip_archive have been patched accordingly,
                            # we always end up here
                            except SystemExit:
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{identifier}' is a local scan target",
                                    cm.output
                                )
                                self.assertIn(
                                    f"DEBUG:guarddog:Considering that '{identifier}' is a local diff scan target",
                                    cm.output
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{identifier}' is a remote scan target",
                                    cm.output
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{identifier}' is a remote diff scan target",
                                    cm.output
                                )

        # Targets are neither files nor directories
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_diff_remote', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan(identifier, None, diff, (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{identifier}' is a local scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{identifier}' is a local diff scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{identifier}' is a remote scan target",
                        cm.output
                    )
                    self.assertIn(
                        f"DEBUG:guarddog:Considering that '{identifier}' is a remote diff scan target",
                        cm.output
                    )

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

    def _test_local_directory_template(self, directory: str):
        # `directory` is a directory
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan(directory, "0.1.0", None, (), (), None, False, ECOSYSTEM.PYPI)
                self.assertIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a local scan target",
                    cm.output
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a local diff scan target",
                    cm.output
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a remote scan target",
                    cm.output
                )
                self.assertNotIn(
                    f"DEBUG:guarddog:Considering that '{directory}' is a remote diff scan target",
                    cm.output
                )

        # `directory` is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_remote', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan(directory, "0.1.0", None, (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a local scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a local diff scan target",
                        cm.output
                    )
                    self.assertIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a remote scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{directory}' is a remote diff scan target",
                        cm.output
                    )

    def _test_local_file_template(self, filename: str):
        # `filename` is a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = True
                with mock.patch("tarsafe.is_tarfile") as is_tar:
                    is_tar.return_value = False
                    with mock.patch("zipfile.is_zipfile") as is_zip:
                        is_zip.return_value = False
                        with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                            try:
                                with self.assertLogs("guarddog", level="DEBUG") as cm:
                                    guarddog.cli._scan(filename, "0.1.0", None, (), (), None, False, ECOSYSTEM.PYPI)
                            except SystemExit:
                                self.assertIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a local scan target",
                                    cm.output
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a local diff scan target",
                                    cm.output
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a remote scan target",
                                    cm.output
                                )
                                self.assertNotIn(
                                    f"DEBUG:guarddog:Considering that '{filename}' is a remote diff scan target",
                                    cm.output
                                )

        # `filename` is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_remote', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan(filename, "0.1.0", None, (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a local scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a local diff scan target",
                        cm.output
                    )
                    self.assertIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a remote scan target",
                        cm.output
                    )
                    self.assertNotIn(
                        f"DEBUG:guarddog:Considering that '{filename}' is a remote diff scan target",
                        cm.output
                    )


if __name__ == "__main__":
    unittest.main()
