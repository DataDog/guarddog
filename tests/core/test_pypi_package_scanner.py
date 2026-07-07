from guarddog.scanners import PypiPackageScanner


def _package_info():
    return {
        "info": {"version": "1.0"},
        "releases": {
            "1.0": [
                {
                    "filename": "aws-dd-forwarder-1.0-py3-none-any.whl",
                    "url": (
                        "https://files.pythonhosted.org/packages/ab/cd/"
                        "ef01/aws-dd-forwarder-1.0-py3-none-any.whl"
                    ),
                },
                {
                    "filename": "aws-dd-forwarder-1.0.tar.gz",
                    "url": (
                        "https://files.pythonhosted.org/packages/f8/57/"
                        "87be/aws-dd-forwarder-1.0.tar.gz"
                    ),
                },
            ]
        },
    }


def test_get_package_dist_path_returns_first_supported_archive_path():
    scanner = PypiPackageScanner()
    path = scanner.get_package_dist_path(_package_info(), "1.0")
    assert path == "/packages/ab/cd/ef01/aws-dd-forwarder-1.0-py3-none-any.whl"


def test_get_package_dist_path_defaults_to_latest_version():
    scanner = PypiPackageScanner()
    path = scanner.get_package_dist_path(_package_info())
    assert path == "/packages/ab/cd/ef01/aws-dd-forwarder-1.0-py3-none-any.whl"


def test_get_package_dist_path_none_when_no_supported_archive():
    scanner = PypiPackageScanner()
    package_info = {
        "info": {"version": "1.0"},
        "releases": {
            "1.0": [{"filename": "aws-dd-forwarder-1.0.metadata", "url": "https://x/y"}]
        },
    }
    assert scanner.get_package_dist_path(package_info, "1.0") is None


def test_get_package_dist_path_none_for_unknown_version():
    scanner = PypiPackageScanner()
    assert scanner.get_package_dist_path(_package_info(), "9.9") is None
