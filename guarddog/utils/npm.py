"""Shared helpers for resolving npm package versions from the registry."""

import logging
import re

import requests
from semantic_version import NpmSpec, Version  # type: ignore

log = logging.getLogger("guarddog")

# Matches npm alias specifiers, e.g. "npm:react@19.2.3" or "npm:@scope/pkg@^1".
NPM_ALIAS_PATTERN = re.compile(
    r"^npm:(?P<package>@[^/@\s]+/[^@\s]+|[^@\s]+)(?:@(?P<selector>.+))?$"
)


def resolve_npm_alias(package_name: str, selector: str) -> tuple[str, str]:
    """Normalize an npm alias so scanning targets the real package.

    ex: ("alias", "npm:react@19.2.3") -> ("react", "19.2.3").
    Non-alias specifiers are returned unchanged.
    """
    match = NPM_ALIAS_PATTERN.match(selector)
    if match is None:
        return package_name, selector
    return match.group("package"), match.group("selector") or "*"


def find_all_versions(package_name: str) -> set[str]:
    """Retrieve all published versions of a package from the npm registry."""
    url = f"https://registry.npmjs.org/{package_name}"
    log.debug(f"Retrieving npm package metadata from {url}")
    response = requests.get(url)
    if response.status_code != 200:
        log.debug(f"No version available, status code {response.status_code}")
        return set()

    data = response.json()
    versions = set(data["versions"].keys())
    log.debug(f"Retrieved versions {', '.join(versions)}")
    return versions


def get_matched_versions(
    versions: set[str], semver_range: str, exhaustive: bool = False
) -> set[str]:
    """Return the versions matching a semver selector.

    When `exhaustive` is False only the single highest matching version is kept.
    An unparseable range is returned verbatim so it can still be scanned as-is.
    """
    try:
        spec = NpmSpec(semver_range)
        result = [Version(m) for m in versions if spec.match(Version(m))]
    except ValueError:
        return {semver_range}

    if not exhaustive and result:
        result = [sorted(result).pop()]

    return {str(r) for r in result}


def highest_matching_version(package_name: str, semver_range: str) -> str | None:
    """Resolve a semver range to the highest published version that matches it.

    Returns None when the package has no published versions, none match, or the
    range is not a concrete semver selector (e.g. a URL or git dependency) so the
    caller can fall back to scanning the latest version.
    """
    matched = get_matched_versions(find_all_versions(package_name), semver_range)
    valid = []
    for m in matched:
        try:
            valid.append(Version(m))
        except ValueError:
            continue
    if not valid:
        return None
    return str(sorted(valid).pop())
