import tempfile

from guarddog.scanners import NPMPackageScanner


def test_download_and_get_package_info():
    scanner = NPMPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        data = scanner.download_and_get_package_info(tmpdirname, "minivlad")
        print()
    pass
