import os
import unittest
from pathlib import Path

from semgrep.test import generate_test_results

cwd = os.path.os.path.abspath(__file__)

class TestSourceCodeAnalysis(unittest.TestCase):
    """_summary_

    Args:
        unittest (_type_): _description_
    """
    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)
    
if __name__ == "__main__":
    unittest.main()
    generate_test_results(target=Path("./semgrep_tests/base64-strings.py"),
                        config=Path("./pysecurity/source_code_analysis/semgrep/base64-strings.yml"),
                        json_output=False,
                        strict=False,
                        deep=False)
