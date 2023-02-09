import os.path
import tempfile

import pytest
from sarif.loader import load_sarif_file

from guarddog.cli import _verify
from guarddog.ecosystems import ECOSYSTEM

dir_path = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize("manifest, ecosystem, warning_count", [
    ("package.json", ECOSYSTEM.NPM, 3), ("requirements.txt", ECOSYSTEM.PYPI, 2)
])
def test_sarif_output(manifest, ecosystem, warning_count):
    raw_output = _verify(
        os.path.join(dir_path, "..", "core", "resources", manifest),
        (),
        (),
        "sarif",
        False,
        ecosystem
    )
    with tempfile.TemporaryDirectory() as tmp_dirname:
        with open(os.path.join(tmp_dirname, "results.sarif"), "w") as fd:
            fd.write(raw_output)
        sarif_data = load_sarif_file(os.path.join(tmp_dirname, "results.sarif"))
        stats = sarif_data.get_result_count_by_severity()
        assert stats["warning"] == warning_count
