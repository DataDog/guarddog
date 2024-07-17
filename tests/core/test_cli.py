import unittest
import unittest.mock as mock

import guarddog.cli
import guarddog.scanners.scanner as scanner
from guarddog.ecosystems import ECOSYSTEM


class TestCli(unittest.TestCase):

    def test_local_target(self):
        # /tmp/foo is a directory
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch("os.listdir") as listdir:
                listdir.return_value = []
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan("/tmp/foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                self.assertIn(
                    "DEBUG:guarddog:Considering that '/tmp/foo' is a local directory",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that '/tmp/foo' is a local file",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that '/tmp/foo' is a remote target",
                    cm.output
                )

        # /tmp/foo is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan("/tmp/foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that '/tmp/foo' is a local directory",
                        cm.output
                    )
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that '/tmp/foo' is a local file",
                        cm.output
                    )
                    self.assertIn(
                        "DEBUG:guarddog:Considering that '/tmp/foo' is a remote target",
                        cm.output
                    )

        # ./foo is a directory
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch("os.listdir") as listdir:
                listdir.return_value = []
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan("./foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                self.assertIn(
                    "DEBUG:guarddog:Considering that './foo' is a local directory",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that './foo' is a local file",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that './foo' is a remote target",
                    cm.output
                )

        # ./foo is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan("./foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that './foo' is a local directory",
                        cm.output
                    )
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that './foo' is a local file",
                        cm.output
                    )
                    self.assertIn(
                        "DEBUG:guarddog:Considering that './foo' is a remote target",
                        cm.output
                    )

        # ../foo is a directory
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = True
            with mock.patch("os.listdir") as listdir:
                listdir.return_value = []
                with self.assertLogs("guarddog", level="DEBUG") as cm:
                    guarddog.cli._scan("../foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                self.assertIn(
                    "DEBUG:guarddog:Considering that '../foo' is a local directory",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that '../foo' is a local file",
                    cm.output
                )
                self.assertNotIn(
                    "DEBUG:guarddog:Considering that '../foo' is a remote target",
                    cm.output
                )

        # ../foo is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan("../foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that '../foo' is a local directory",
                        cm.output
                    )
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that '../foo' is a local file",
                        cm.output
                    )
                    self.assertIn(
                        "DEBUG:guarddog:Considering that '../foo' is a remote target",
                        cm.output
                    )

        # . is a directory
        with mock.patch("os.listdir") as listdir:
            listdir.return_value = []
            with self.assertLogs("guarddog", level="DEBUG") as cm:
                guarddog.cli._scan(".", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
            self.assertIn(
                "DEBUG:guarddog:Considering that '.' is a local directory",
                cm.output
            )
            self.assertNotIn(
                "DEBUG:guarddog:Considering that '.' is a local file",
                cm.output
            )
            self.assertNotIn(
                "DEBUG:guarddog:Considering that '.' is a remote target",
                cm.output
            )

        # foo is a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = True
                with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan("foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that 'foo' is a local directory",
                        cm.output
                    )
                    self.assertIn(
                        "DEBUG:guarddog:Considering that 'foo' is a local file",
                        cm.output
                    )
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that 'foo' is a remote target",
                        cm.output
                    )

        # foo is neither a directory nor a file
        with mock.patch("os.path.isdir") as isdir:
            isdir.return_value = False
            with mock.patch("os.path.isfile") as isfile:
                isfile.return_value = False
                with mock.patch.object(scanner.PackageScanner, 'scan_local', return_value={}) as _:
                    with self.assertLogs("guarddog", level="DEBUG") as cm:
                        guarddog.cli._scan("foo", "0.1.0", (), (), None, False, ECOSYSTEM.PYPI)
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that 'foo' is a local directory",
                        cm.output
                    )
                    self.assertNotIn(
                        "DEBUG:guarddog:Considering that 'foo' is a local file",
                        cm.output
                    )
                    self.assertIn(
                        "DEBUG:guarddog:Considering that 'foo' is a remote target",
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


if __name__ == "__main__":
    unittest.main()
