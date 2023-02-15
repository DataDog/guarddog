from guarddog.analyzer.metadata.pypi import PypiSinglePythonFileDetector
from unittest.mock import patch

pypi_detector = PypiSinglePythonFileDetector()

class TestSinglePythonFile:
    @patch('os.walk')
    def test_no_python_file(self, mock_walk):
        mock_walk.return_value = [(".", ["dir"], ["file"])]
        matches, _ = pypi_detector.detect({}, "/do/not/care")
        assert matches

    @patch('os.walk')
    def test_single_python_file(self, mock_walk):
        mock_walk.return_value = [(".", ["dir"], ["file.py", "file.txt"])]
        matches, _ = pypi_detector.detect({}, "/do/not/care")
        assert matches

    @patch('os.walk')
    def test_many_python_file(self, mock_walk):
        mock_walk.return_value = [(".", ["dir"], [f"file{i}.py" for i in range(100)])]
        matches, _ = pypi_detector.detect({}, "/do/not/care")
        assert not matches
