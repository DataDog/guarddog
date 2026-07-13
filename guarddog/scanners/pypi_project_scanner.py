import logging
import os
import re
from typing import Callable, List, Optional

from packaging.requirements import Requirement
import requests
from packaging.specifiers import SpecifierSet, Version

try:
    import tomllib  # Python >= 3.11
except ImportError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from guarddog.scanners.pypi_package_scanner import PypiPackageScanner
from guarddog.scanners.scanner import Dependency, DependencyVersion, ProjectScanner
from guarddog.utils.config import VERIFY_EXHAUSTIVE_DEPENDENCIES

log = logging.getLogger("guarddog")


class PypiRequirementsScanner(ProjectScanner):
    """
    Scans the Python dependency files of a project: requirements.txt,
    pyproject.toml (PEP 621 and Poetry), and poetry.lock / uv.lock lockfiles.

    Attributes:
        package_scanner (PackageScanner): Scanner for individual packages
    """

    def __init__(self) -> None:
        super().__init__(PypiPackageScanner())

    def _sanitize_requirements(self, requirements: list[str]) -> list[str]:
        """
        Filters out non-requirement specifications from a requirements specification

        Args:
            requirements (str): PEP440 styled dependency specification text

        Returns:
            list[str]: sanitized lines containing only version specifications
        """

        sanitized_lines = []

        for line in requirements:
            is_requirement = re.match(r"\w", line)

            if not is_requirement:
                sanitized_lines.append("")  # empty line to keep the line number
                continue

            if "\\" in line:
                line = line.replace("\\", "")

            stripped_line = line.strip()
            sanitized_lines.append(stripped_line)

        return sanitized_lines

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        """
        Parses a Python dependency file and finds all valid versions of each
        dependency. Supports requirements.txt, pyproject.toml (PEP 621 and
        Poetry sections), and poetry.lock / uv.lock lockfiles.

        Args:
            raw_requirements (str): contents of the dependency file

        Returns:
            dict: mapping of dependencies to valid versions
        """
        toml_result = self._parse_toml_requirements(raw_requirements)
        if toml_result is not None:
            return toml_result

        requirements = raw_requirements.splitlines()
        sanitized_requirements = self._sanitize_requirements(requirements)

        def find_location(requirement: Requirement) -> int:
            return next(
                iter(
                    [
                        ix
                        for ix, line in enumerate(requirements)
                        if str(requirement) in line
                    ]
                ),
                0,
            )

        dependencies = self._resolve_requirement_lines(
            sanitized_requirements, find_location
        )

        has_content_lines = any(
            line.strip() and not line.lstrip().startswith(("#", "-"))
            for line in requirements
        )
        if not dependencies and has_content_lines:
            log.warning(
                "No valid Python requirements found in the provided file. Is it "
                "really a requirements.txt, pyproject.toml, or lockfile?"
            )

        return dependencies

    # ------------------------------------------------------------------ #
    # pyproject.toml / lockfile support
    # ------------------------------------------------------------------ #

    def _parse_toml_requirements(
        self, raw_requirements: str
    ) -> Optional[List[Dependency]]:
        """
        Detects and parses TOML dependency files. Returns None when the input
        is not TOML (i.e. it should be treated as requirements.txt).
        """
        try:
            data = tomllib.loads(raw_requirements)
        except Exception:
            return None
        if not isinstance(data, dict) or not data:
            return None

        requirement_lines: Optional[list[str]] = None
        if "project" in data or ("tool" in data and "poetry" in data.get("tool", {})):
            requirement_lines = self._pyproject_requirement_lines(data)
        elif isinstance(data.get("package"), list):
            # poetry.lock / uv.lock: [[package]] entries with exact pins
            requirement_lines = [
                f"{p['name']}=={p['version']}"
                for p in data["package"]
                if isinstance(p, dict) and "name" in p and "version" in p
            ]
        if requirement_lines is None:
            return None

        raw_lines = raw_requirements.splitlines()

        def find_location(requirement: Requirement) -> int:
            return next(
                iter(
                    [
                        ix
                        for ix, line in enumerate(raw_lines)
                        if requirement.name in line
                    ]
                ),
                0,
            )

        return self._resolve_requirement_lines(requirement_lines, find_location)

    def _pyproject_requirement_lines(self, data: dict) -> list[str]:
        """
        Extracts PEP 508 requirement strings from a parsed pyproject.toml,
        covering PEP 621 ([project]) and Poetry ([tool.poetry]) layouts.
        """
        lines: list[str] = []

        project = data.get("project", {})
        if isinstance(project, dict):
            deps = project.get("dependencies", [])
            if isinstance(deps, list):
                lines.extend(d for d in deps if isinstance(d, str))
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group_deps in optional.values():
                    if isinstance(group_deps, list):
                        lines.extend(d for d in group_deps if isinstance(d, str))

        poetry = data.get("tool", {}).get("poetry", {})
        if isinstance(poetry, dict):
            poetry_dep_tables = [
                poetry.get("dependencies", {}),
                poetry.get("dev-dependencies", {}),  # legacy Poetry
            ]
            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, dict):
                        poetry_dep_tables.append(group.get("dependencies", {}))

            for table in poetry_dep_tables:
                if not isinstance(table, dict):
                    continue
                for name, spec in table.items():
                    for line in self._poetry_dependency_to_pep508(name, spec):
                        lines.append(line)

        return lines

    def _poetry_dependency_to_pep508(self, name: str, spec) -> list[str]:
        """
        Converts one Poetry dependency entry to PEP 508 requirement strings.
        Returns an empty list for entries that cannot be verified against PyPI
        (the python constraint itself, git/path/url dependencies).
        """
        if name.lower() == "python":
            return []
        if isinstance(spec, str):
            constraint = self._poetry_constraint_to_pep440(spec)
            return [f"{name}{constraint}"]
        if isinstance(spec, dict):
            if any(key in spec for key in ("git", "path", "url")):
                log.debug(
                    f"Skipping {name}: git/path/url dependencies cannot be "
                    "verified against PyPI"
                )
                return []
            version = spec.get("version")
            if isinstance(version, str):
                constraint = self._poetry_constraint_to_pep440(version)
                return [f"{name}{constraint}"]
            return [name]
        if isinstance(spec, list):
            lines: list[str] = []
            for sub_spec in spec:
                lines.extend(self._poetry_dependency_to_pep508(name, sub_spec))
            return lines
        return [name]

    @staticmethod
    def _poetry_constraint_to_pep440(constraint: str) -> str:
        """
        Translates a Poetry version constraint to PEP 440. Caret and tilde
        ranges are expanded; bare versions become exact pins; PEP 440 style
        constraints pass through unchanged.
        """
        constraint = constraint.strip()
        if constraint in ("", "*"):
            return ""
        if "||" in constraint:
            # Poetry OR-syntax has no PEP 440 equivalent; fall back to any
            # version so the package is still scanned.
            log.debug(f"Cannot translate Poetry constraint {constraint!r} to PEP 440")
            return ""
        if constraint.startswith("~="):
            return constraint
        if constraint[0] in ("^", "~"):
            operator, base = constraint[0], constraint[1:].strip()
            match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?$", base)
            if not match:
                return f">={base}"
            parts = [int(p) for p in match.groups() if p is not None]
            if operator == "^":
                upper = None
                for i, part in enumerate(parts):
                    if part != 0:
                        upper = parts[:i] + [part + 1]
                        break
                if upper is None:  # ^0 / ^0.0 / ^0.0.0
                    upper = parts[:-1] + [parts[-1] + 1]
            else:  # ~
                if len(parts) == 1:
                    upper = [parts[0] + 1]
                else:
                    upper = [parts[0], parts[1] + 1]
            return f">={base},<{'.'.join(str(p) for p in upper)}"
        if constraint[0].isdigit():
            return f"=={constraint}"
        return constraint

    # ------------------------------------------------------------------ #
    # Shared resolution core
    # ------------------------------------------------------------------ #

    def _resolve_requirement_lines(
        self,
        requirement_lines: list[str],
        find_location: Callable[[Requirement], int],
    ) -> List[Dependency]:
        """
        Resolves PEP 508 requirement lines against PyPI and builds the
        Dependency list. find_location maps a parsed requirement back to a
        0-based line index in the original file for reporting.
        """
        dependencies: List[Dependency] = []

        def get_matched_versions(versions: set[str], semver_range: str) -> set[str]:
            """
            Retrieves all versions that match a given semver selector
            """
            result = []

            # Filters to specified versions. SpecifierSet handles both single
            # constraints and comma-separated sets (e.g. ">=2.2,<3").
            try:
                matching_versions = versions
                if semver_range:
                    spec = SpecifierSet(semver_range)
                    matching_versions = set(spec.filter(versions))
                result = [Version(m) for m in matching_versions]
            except ValueError:
                # use it raw (e.g. direct URL / git references)
                return set([semver_range])

            # If just the best matched version scan is required we only keep one
            if not VERIFY_EXHAUSTIVE_DEPENDENCIES and result:
                result = [sorted(result).pop()]

            return set([str(r) for r in result])

        def find_all_versions(package_name: str) -> set[str]:
            """
            This helper function retrieves all versions availables for the package
            """
            url = "https://pypi.org/pypi/%s/json" % (package_name,)
            log.debug(f"Retrieving PyPI package metadata information from {url}")
            response = requests.get(url)
            if response.status_code != 200:
                log.debug(f"No version available, status code {response.status_code}")
                return set()

            data = response.json()
            versions = set(sorted(data["releases"].keys()))
            log.debug(f"Retrieved versions {', '.join(versions)}")
            return versions

        def safe_parse_requirements(req):
            """
            This helper function yields one valid requirement line at a time
            """
            for req_line in req:
                if not req_line.strip():
                    continue
                try:
                    yield Requirement(req_line)
                except Exception as e:
                    log.error(
                        f"Error when parsing requirements, received error {str(e)}. This entry will be "
                        "ignored.\n"
                    )
                    yield None

        try:
            for requirement in safe_parse_requirements(requirement_lines):
                if requirement is None:
                    continue

                versions = get_matched_versions(
                    find_all_versions(requirement.name),
                    (
                        requirement.url
                        if requirement.url
                        else str(requirement.specifier)
                    ),
                )

                if len(versions) == 0:
                    log.error(f"Package/Version {requirement.name} not on PyPI\n")
                    continue

                idx = find_location(requirement)

                dep_versions = list(
                    map(
                        lambda d: DependencyVersion(version=d, location=idx + 1),
                        versions,
                    )
                )

                # find the dep with the same name or create a new one
                dep = next(
                    filter(
                        lambda d: d.name == requirement.name,
                        dependencies,
                    ),
                    None,
                )
                if not dep:
                    dep = Dependency(name=requirement.name, versions=set())
                    dependencies.append(dep)

                dep.versions.update(dep_versions)

        except Exception as e:
            log.error(f"Received error {str(e)}")

        return dependencies

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if re.match(
                    r"^(requirements(-dev)?\.txt|pyproject\.toml|poetry\.lock|uv\.lock)$",
                    name,
                    flags=re.IGNORECASE,
                ):
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
