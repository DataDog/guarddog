import logging
import os
from typing import Optional

import pygit2
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

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        if name is None:
            raise ValueError("Detector needs the name of the package")
        if path is None:
            raise ValueError("Detector needs the path of the package")

        log.debug(
            f"Running repository integrity mismatch heuristic on RubyGems package {name}"
        )

        source_code_uri = package_info.get("source_code_uri")
        homepage_uri = package_info.get("homepage_uri")

        github_url = normalize_github_url(source_code_uri)
        if github_url is None:
            github_url = normalize_github_url(homepage_uri)

        if github_url is None:
            return False, "Could not find a GitHub URL in the gem metadata"

        if version is None:
            version = package_info.get("version")
        if version is None:
            raise ValueError("Could not determine version to scan")

        log.debug(f"Using GitHub URL {github_url}")

        tmp_dir = os.path.dirname(path)
        repo_path = os.path.join(tmp_dir, "sources", name)

        try:
            repo = pygit2.clone_repository(url=github_url, path=repo_path)
        except pygit2.GitError as git_error:
            return False, f"Could not clone repository: {str(git_error)}"
        except Exception as e:
            return False, f"Error cloning repository: {str(e)}"

        tag_candidates = self.find_suitable_tags(repo, version)

        if len(tag_candidates) == 0:
            return False, f"Could not find a tag matching version {version}"

        target_tag = tag_candidates[-1]

        mismatch = self.find_mismatch_for_tag(repo, target_tag, path, repo_path)
        if len(mismatch) == 0:
            return False, ""

        message = "\n".join(map(lambda x: "* " + x["file"], mismatch))
        return (
            True,
            f"Files in gem differ from GitHub repository for version {version}:\n{message}",
        )