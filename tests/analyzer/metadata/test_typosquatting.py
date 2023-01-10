import pytest

from guarddog.analyzer.metadata.npm import NPMTyposquatDetector
from guarddog.analyzer.metadata.pypi import PypiTyposquatDetector
from tests.analyzer.metadata.resources.sample_project_info import generate_project_info


class TestTyposquatting:
    pypi_detector = PypiTyposquatDetector()
    npm_detector = NPMTyposquatDetector()
    pypi_typosquats = [
        ("ans1crypto", "asn1crypto"),
        ("colourama", "colorama"),
        ("djanga", "django"),
        ("httplib3", "httplib2"),
        ("htpplib2", "httplib2"),
        ("mumpy", "numpy"),
        ("nmap-python", "python-nmap"),
        ("openvc", "opencv-python"),
        ("pyflaces", "pyflakes"),
        ("py-jwt", "pyjwt"),
        ("pyjtw", "pyjwt"),
        ("python-mongo", "pymongo"),
        ("python-mysql", "mysql-python"),
        ("python-openssl", "pyopenssl"),
        ("reqeusts-oauthlib", "requests-oauthlib"),
        ("request-oauthlib", "requests-oauthlib"),
        ("tenserflow", "tensorflow"),
        ("pythonkafka", "kafka-python"),
        ("virtualnv", "virtualenv"),
    ]

    npm_typosquats = [
        ("expresss", "express"),
        ("wich-boxed-primitive", "which-boxed-primitive"),
        ("twetnacl", "tweetnacl"),
        ("jest-watchers", "jest-watcher"),
        ("shpk", "sshpk"),
        ("requests", "request")
    ]

    negative_cases = ["hello-world", "foo", "bar"]
    same_names = ["pip", "Numpy", "openCv-python", "requests_oauthlib"]

    @pytest.mark.parametrize("typo_name, real_name", pypi_typosquats)
    def test_pypi_typosquats(self, typo_name, real_name):
        project_info = generate_project_info("name", typo_name)
        matches, message = self.pypi_detector.detect(project_info)
        assert matches and real_name in message

    @pytest.mark.parametrize("typo_name, real_name", npm_typosquats)
    def test_npm_typosquats(self, typo_name, real_name):
        project_info = {"name": typo_name}
        matches, message = self.npm_detector.detect(project_info)
        assert matches and real_name in message

    @pytest.mark.parametrize("name", negative_cases + same_names)
    def test_nontyposquats(self, name):
        project_info = generate_project_info("name", name)
        matches, _ = self.pypi_detector.detect(project_info)
        assert not matches

    def test_no_duplicate_errors(self):
        """
        Verify that a package with a typo in the name only reports 1 error

        Regression test for https://github.com/DataDog/guarddog/issues/71
        """
        result = self.pypi_detector.get_typosquatted_package("pdfminer.sid")
        assert len(result) == 1

    def test_normalize_names(self):
        """
        Verify that a package with 1 or more dots(.), hyphens(-) or underscore(_) gets normalized
        to avoid false positives

        Regression test for https://github.com/DataDog/guarddog/issues/71
        """
        result = self.pypi_detector.get_typosquatted_package("pdfminer...---___six")
        assert len(result) == 0
