import tempfile

from guarddog.scanners import RubyGemsPackageScanner


def test_download_and_get_package_info_with_version():
    scanner = RubyGemsPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        test_gem = "rake"
        test_version = "13.0.6"

        data, path = scanner.download_and_get_package_info(
            tmpdirname, test_gem, test_version
        )

        assert path
        assert path.endswith("/rake")
        assert data["name"] == "rake"


def test_download_and_get_package_info_without_version():
    scanner = RubyGemsPackageScanner()
    with tempfile.TemporaryDirectory() as tmpdirname:
        test_gem = "rake"

        data, path = scanner.download_and_get_package_info(tmpdirname, test_gem)

        assert path
        assert path.endswith("/rake")
        assert data["name"] == "rake"
        assert data["version"] != ""


def test_get_gem_info():
    scanner = RubyGemsPackageScanner()
    info = scanner._get_gem_info("rails")

    assert info["name"] == "rails"
    assert "version" in info
    assert "authors" in info
