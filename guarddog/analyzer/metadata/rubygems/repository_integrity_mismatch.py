import hashlib
import logging
import os
import re
from typing import Optional

import pygit2
import urllib3.util

from guarddog.analyzer.metadata.repository_integrity_mismatch import IntegrityMismatch

log = logging.getLogger("guarddog")

EXCLUDED_EXTENSIONS = [".md", ".txt", ".rdoc"]


def get_file_hash(path):
    with open(path, "rb") as f:
        file_contents = f.read()
        hash_object = hashlib.sha256()
        hash_object.update(file_contents)
        return hash_object.hexdigest()


def find_suitable_tags(repo, version):
    tags_regex = re.compile("^refs/tags/(.*)")
    tags = []
    for ref in repo.references:
        match = tags_regex.match(ref)
        if match is not None:
            tags.append(match.group(0))

    tag_candidates = []
    for tag_name in tags:
        # Extract just the tag ref (e.g., "refs/tags/v1.0" -> "v1.0")
        tag_ref = tag_name.rsplit("/", 1)[-1]
        if tag_ref == version or tag_ref == f"v{version}":
            tag_candidates.append(tag_name)
    return tag_candidates


def exclude_result(file_name):
    for extension in EXCLUDED_EXTENSIONS:
        if file_name.endswith(extension):
            return True
    return False


def find_mismatch_for_tag(repo, tag, base_path, repo_path):
    repo.checkout(tag)
    mismatch = []
    for root, dirs, files in os.walk(base_path):
        relative_path = os.path.relpath(root, base_path)
        repo_root = os.path.join(repo_path, relative_path)
        if not os.path.exists(repo_root):
            continue
        repo_files = list(
            filter(
                lambda x: os.path.isfile(os.path.join(repo_root, x)),
                os.listdir(repo_root),
            )
        )
        for file_name in repo_files:
            if file_name not in files:
                continue
            if exclude_result(file_name):
                continue
            repo_hash = get_file_hash(os.path.join(repo_root, file_name))
            pkg_hash = get_file_hash(os.path.join(root, file_name))
            if repo_hash != pkg_hash:
                res = {
                    "file": os.path.join(relative_path, file_name),
                    "repo_sha256": repo_hash,
                    "pkg_sha256": pkg_hash,
                }
                mismatch.append(res)
    return mismatch


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

        tag_candidates = find_suitable_tags(repo, version)

        if len(tag_candidates) == 0:
            return False, f"Could not find a tag matching version {version}"

        target_tag = tag_candidates[-1]

        mismatch = find_mismatch_for_tag(repo, target_tag, path, repo_path)
        if len(mismatch) == 0:
            return False, ""

        message = "\n".join(map(lambda x: "* " + x["file"], mismatch))
        return (
            True,
            f"Files in gem differ from GitHub repository for version {version}:\n{message}",
        )
