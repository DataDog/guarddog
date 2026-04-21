import configparser
import logging
import os
import re
from typing import Optional

from guarddog.analyzer.metadata.metadata_mismatch import MetadataMismatchDetector

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

log = logging.getLogger("guarddog")


def _normalize_dep_name(dep: str) -> str:
    """Normalize a dependency name per PEP 503: lowercase, collapse [-_.] to -."""
    # Strip version specifiers, extras, and markers
    name = re.split(r"[\s;>=<!\[(\)]", dep)[0].strip()
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requires_dist(requires_dist: list[str] | None) -> set[str]:
    """Extract normalized dep names from PyPI requires_dist list."""
    if not requires_dist:
        return set()
    return {_normalize_dep_name(dep) for dep in requires_dist if dep.strip()}


def _parse_pyproject_toml(path: str) -> set[str] | None:
    """Extract dependencies from pyproject.toml [project].dependencies."""
    if tomllib is None:
        return None

    pyproject_path = os.path.join(path, "pyproject.toml")
    if not os.path.isfile(pyproject_path):
        return None

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", None)
        if deps is None:
            return None
        return {_normalize_dep_name(dep) for dep in deps if dep.strip()}
    except Exception as e:
        log.debug(f"Failed to parse pyproject.toml: {e}")
        return None


def _parse_setup_cfg(path: str) -> set[str] | None:
    """Extract dependencies from setup.cfg [options].install_requires."""
    setup_cfg_path = os.path.join(path, "setup.cfg")
    if not os.path.isfile(setup_cfg_path):
        return None

    try:
        cfg = configparser.ConfigParser()
        cfg.read(setup_cfg_path)
        raw = cfg.get("options", "install_requires", fallback=None)
        if raw is None:
            return None
        deps = [line.strip() for line in raw.strip().splitlines() if line.strip()]
        return {_normalize_dep_name(dep) for dep in deps}
    except Exception as e:
        log.debug(f"Failed to parse setup.cfg: {e}")
        return None


class PypiMetadataMismatchDetector(MetadataMismatchDetector):
    """Compares PyPI registry requires_dist against pyproject.toml/setup.cfg dependencies.

    Catches attacks where the registry metadata declares different dependencies
    than what the actual package manifest specifies, which can indicate hidden
    dependency injection during the build process.
    """

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())

        # Get requires_dist from PyPI metadata
        requires_dist = package_info.get("info", {}).get("requires_dist")
        registry_deps = _parse_requires_dist(requires_dist)

        # Find the package subdirectory (sdist extracts to name-version/)
        pkg_name = name or package_info.get("info", {}).get("name", "")
        pkg_dir = _find_package_dir(path, pkg_name)
        if pkg_dir is None:
            return False, None

        # Try pyproject.toml first, then setup.cfg
        manifest_deps = _parse_pyproject_toml(pkg_dir)
        manifest_source = "pyproject.toml"
        if manifest_deps is None:
            manifest_deps = _parse_setup_cfg(pkg_dir)
            manifest_source = "setup.cfg"
        if manifest_deps is None:
            # No parseable manifest found
            return False, None

        # Compare: deps in manifest but not in registry (hidden injection)
        # and deps in registry but not in manifest (phantom deps)
        only_in_manifest = manifest_deps - registry_deps
        only_in_registry = registry_deps - manifest_deps

        if not only_in_manifest and not only_in_registry:
            return False, None

        description = (
            f"Dependency mismatch between PyPI metadata and {manifest_source}:\n"
        )
        if only_in_manifest:
            description += (
                f"  In {manifest_source} but NOT in PyPI metadata: "
                f"{', '.join(sorted(only_in_manifest))}\n"
            )
        if only_in_registry:
            description += (
                f"  In PyPI metadata but NOT in {manifest_source}: "
                f"{', '.join(sorted(only_in_registry))}\n"
            )

        return True, description


def _find_package_dir(path: str, name: str) -> Optional[str]:
    """Find the package subdirectory inside the extracted archive."""
    if not os.path.isdir(path):
        return None

    normalized = name.lower().replace("-", "_")
    for entry in os.listdir(path):
        entry_lower = entry.lower()
        if entry_lower.startswith(normalized) or entry_lower.startswith(name.lower()):
            candidate = os.path.join(path, entry)
            if os.path.isdir(candidate):
                return candidate

    # Fallback: check if manifest files exist at root level (wheel extraction)
    if os.path.isfile(os.path.join(path, "pyproject.toml")) or os.path.isfile(
        os.path.join(path, "setup.cfg")
    ):
        return path

    return None
