# FALSE POSITIVE: setuptools/jaraco style. platform.system() only picks an
# rmtree error handler; urllib.request.urlopen() downloads an unrelated tarball.
# The two never share data, but the rule correlates them anyway.
import platform
import urllib.request

def _on_rmtree_error(func, path, exc):
    if platform.system() == "Windows":
        os.chmod(path, 0o700)

def fetch_tarball(url, dest):
    with urllib.request.urlopen(url) as resp:
        dest.write(resp.read())
