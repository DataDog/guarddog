# Benign regression test for threat-filesystem-autostart.
# A profile attribute or identifier is not a shell startup file, and urlopen
# must not satisfy the file-write condition.
# (FPs from semgrep, dbt-snowflake, pytensor, testcontainers.)
from semgrep.profile_manager import ProfileManager


class Connection:
    def __init__(self, profile):
        self.profile = profile
        self.query_header = SnowflakeMacroQueryStringSetter(self.profile)

    def fetch(self, url):
        with urlopen(url) as response:
            return response.read()

    def stats(self, config):
        if config.profile:
            return self.profile.dependencies


# Installer-style .pth writes are benign: setuptools editable installs write
# __editable___*.pth files into site-packages. The __editable___ marker must
# keep this out of the autostart threat.
import os
import site


def write_editable_pth():
    target = os.path.join(site.getsitepackages()[0], "__editable___pkg.pth")
    with open(target, "w") as f:
        f.write("import __editable___pkg_finder; __editable___pkg_finder.install()")
