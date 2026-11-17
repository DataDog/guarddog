import unittest
import unittest.mock as mock

from guarddog.scanners import PypiPackageScanner


class TestScanRemoteScannedFlag(unittest.TestCase):
    """Remote scans must say whether the package was actually scanned (#906)."""

    def test_failed_download_marks_result_unscanned(self):
        scanner = PypiPackageScanner()
        with mock.patch.object(
            scanner,
            "download_and_get_package_info",
            side_effect=Exception("Received status code: 404 from PyPI"),
        ):
            result = scanner.scan_remote("this-package-does-not-exist")
        self.assertIs(result["scanned"], False)
        self.assertEqual(result["issues"], 0)
        self.assertEqual(
            result["errors"]["download-package"], "Received status code: 404 from PyPI"
        )

    def test_successful_scan_marks_result_scanned(self):
        scanner = PypiPackageScanner()
        package_info = {"info": {}, "releases": {}}
        with mock.patch.object(
            scanner,
            "download_and_get_package_info",
            return_value=(package_info, "some-path"),
        ):
            with mock.patch.object(
                scanner.analyzer, "analyze", return_value={"issues": 0}
            ):
                result = scanner.scan_remote("requests")
        self.assertIs(result["scanned"], True)


if __name__ == "__main__":
    unittest.main()
