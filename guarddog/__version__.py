"""Setup version information from pyproject.toml"""
import importlib.metadata

try:
    __version__ = importlib.metadata.version('guarddog')
except importlib.metadata.PackageNotFoundError:
    __version__ = None
