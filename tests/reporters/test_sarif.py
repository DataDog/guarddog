import os.path
import tempfile

import pytest
from _pytest.monkeypatch import MonkeyPatch
from sarif.loader import load_sarif_file

from guarddog.cli import _verify
from guarddog.ecosystems import ECOSYSTEM

dir_path = os.path.dirname(os.path.realpath(__file__))

npm_local_scan_results = [
    {
        "dependency": "mock1",
        "version": "1.0.0",
        "result": {
            "issues": 2,
            "errors": {},
            "results": {
                "typosquatting": None,
                "direct_url_dependency": None,
                "release_zero": None,
                "deceptive_author": None,
                "empty_information": "This package has an empty description on npm",
                "npm_metadata_mismatch": None,
                "unclaimed_maintainer_email_domain": None,
                "bundled_binary": None,
                "potentially_compromised_email_domain": None,
                "npm-exec-base64": [
                    {
                        "location": "package/index.js:3",
                        "code": "eval(atob(str));",
                        "message": "This package contains a call to the `eval` function with a `base64` encoded string as argument.\nThis is a common method used to hide a malicious payload in a module as static analysis will not decode the\nstring.\n",
                    }
                ],
                "npm-install-script": {},
                "shady-links": {},
                "npm-silent-process-execution": {},
                "npm-exfiltrate-sensitive-data": {},
                "npm-dll-hijacking": {},
                "npm-serialize-environment": {},
                "npm-steganography": {},
                "npm-obfuscation": {},
            },
            "path": "/some/path",
        },
    },
    {
        "dependency": "mock2",
        "version": "2.0.0",
        "result": {
            "issues": 2,
            "errors": {},
            "results": {
                "typosquatting": None,
                "direct_url_dependency": None,
                "release_zero": None,
                "deceptive_author": None,
                "empty_information": "This package has an empty description on npm",
                "npm_metadata_mismatch": None,
                "unclaimed_maintainer_email_domain": None,
                "bundled_binary": None,
                "potentially_compromised_email_domain": None,
                "npm-exec-base64": [
                    {
                        "location": "package/index.js:3",
                        "code": "eval(atob(str));",
                        "message": "This package contains a call to the `eval` function with a `base64` encoded string as argument.\nThis is a common method used to hide a malicious payload in a module as static analysis will not decode the\nstring.\n",
                    }
                ],
                "npm-install-script": {},
                "shady-links": {},
                "npm-silent-process-execution": {},
                "npm-exfiltrate-sensitive-data": {},
                "npm-dll-hijacking": {},
                "npm-serialize-environment": {},
                "npm-steganography": {},
                "npm-obfuscation": {},
            },
        },
        "path": "/some/path",
    },
]

pypi_local_scan_results = [
    {
        "dependency": "kicost",
        "version": "1.1.14",
        "result": {
            "issues": 2,
            "errors": {},
            "results": {
                "potentially_compromised_email_domain": None,
                "empty_information": None,
                "deceptive_author": None,
                "release_zero": None,
                "unclaimed_maintainer_email_domain": None,
                "typosquatting": None,
                "single_python_file": None,
                "bundled_binary": None,
                "obfuscation": {},
                "download-executable": {},
                "code-execution": [
                    {
                        "location": "kicost-1.1.14/setup.py:47",
                        "code": "            call(['kicost', '--setup'])",
                        "message": "This package is executing OS commands in the setup.py file",
                    }
                ],
                "silent-process-execution": {},
                "clipboard-access": {},
                "cmd-overwrite": [
                    {
                        "location": "kicost-1.1.14/setup.py:128",
                        "code": "setup(\n    name='kicost',\n    version=kicost.__version__,\n    description=\"Build cost spreadsheet for a KiCad project.\",\n    long_description=readme + '\\n\\n' + history,\n    # long_description_content_type=\"text/reStructuredText\",\n    author...d,\n    }\n)",
                        "message": "This package is overwriting the 'install' command in setup.py",
                    }
                ],
                "dll-hijacking": {},
                "bidirectional-characters": {},
                "exfiltrate-sensitive-data": {},
                "exec-base64": {},
                "steganography": {},
            },
            "path": "/some/path",
        },
    }
]

@pytest.mark.parametrize(
    "manifest, ecosystem, local_scan_results, warning_count",
    [
        ("package.json", ECOSYSTEM.NPM, npm_local_scan_results, 4),
        ("requirements.txt", ECOSYSTEM.PYPI, pypi_local_scan_results, 2),
    ],
)
def test_sarif_output(manifest, ecosystem, local_scan_results, warning_count):

    def monkey_localscan(*args, **kwargs):
        return local_scan_results

    MonkeyPatch().setattr(
        "guarddog.scanners.scanner.ProjectScanner.scan_local", monkey_localscan
    )

    raw_output = _verify(
        os.path.join(dir_path, "..", "core", "resources", manifest),
        (),
        (),
        "sarif",
        False,
        ecosystem,
    )
    with tempfile.TemporaryDirectory() as tmp_dirname:
        with open(os.path.join(tmp_dirname, "results.sarif"), "w") as fd:
            fd.write(raw_output)
        sarif_data = load_sarif_file(os.path.join(tmp_dirname, "results.sarif"))
        stats = sarif_data.get_result_count_by_severity()
        assert stats["warning"] == warning_count
