import logging
from typing import Optional

import urllib3.util

from guarddog.analyzer.metadata.repository_integrity_mismatch import IntegrityMismatch

log = logging.getLogger("guarddog")


def normalize_github_url(url):
    if url is None:
        return None
    url = url.strip()
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git://"):
        url = url.replace("git://", "https://")
    if url.startswith("http://"):
        url = url.replace("http://", "https://")
    parsed = urllib3.util.parse_url(url)
    if parsed.host not in ("github.com", "www.github.com"):
        return None
    return url


class RubyGemsIntegrityMismatchDetector(IntegrityMismatch):
    EXCLUDED_EXTENSIONS = [".md", ".txt", ".rdoc"]

    def extract_github_url(self, package_info, name: str) -> Optional[str]:
        """Extract GitHub URL from RubyGems metadata."""
        source_code_uri = package_info.get("source_code_uri")
        homepage_uri = package_info.get("homepage_uri")

        github_url = normalize_github_url(source_code_uri)
        if github_url is None:
            github_url = normalize_github_url(homepage_uri)

        return github_url

    def get_base_path(self, path: str, name: str) -> str:
        """RubyGems: files are extracted directly to the path."""
        return path

    def get_version(self, package_info, version: Optional[str]) -> Optional[str]:
        """Get version from RubyGems metadata or use provided version."""
        if version is None:
            version = package_info.get("version")
        return version
