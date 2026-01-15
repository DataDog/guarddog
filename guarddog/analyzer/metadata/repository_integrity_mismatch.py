import logging
import os
import re
from abc import abstractmethod
from typing import List, Optional

import pygit2

from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.utils import get_file_hash

log = logging.getLogger("guarddog")


class IntegrityMismatch(Detector):
    """This package contains files that have been tampered with between the source repository and the package CDN"""

    RULE_NAME = "repository_integrity_mismatch"
    EXCLUDED_EXTENSIONS: List[str] = []

    def __init__(self):
        super().__init__(
            name="repository_integrity_mismatch",
            description="Identify packages with a linked GitHub repository "
            "where the package has extra unexpected files",
        )

    @abstractmethod
    def extract_github_url(self, package_info, name: str) -> Optional[str]:
        """
        Extract GitHub URL from package metadata.

        Args:
            package_info: Package metadata dictionary
            name: Package name

        Returns:
            GitHub URL if found, None otherwise
        """
        pass

    @abstractmethod
    def get_base_path(self, path: str, name: str) -> str:
        """
        Get the base path where package files are located.

        Args:
            path: Root extraction path
            name: Package name

        Returns:
            Path to the package source files
        """
        pass

    @abstractmethod
    def get_version(self, package_info, version: Optional[str]) -> Optional[str]:
        """
        Extract version from package info or use provided version.

        Args:
            package_info: Package metadata dictionary
            version: Optional version string

        Returns:
            Version string
        """
        pass

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Template method for detecting repository integrity mismatches.

        This method implements the common algorithm for comparing package files
        with their source repository. Subclasses customize behavior by implementing
        the abstract methods for URL extraction, path resolution, and version handling.
        """
        if name is None:
            return False, "Detector needs the name of the package"
        if path is None:
            return False, "Detector needs the path of the package"

        log.debug(f"Running repository integrity mismatch heuristic on package {name}")

        # Step 1: Extract GitHub URL (ecosystem-specific)
        github_url = self.extract_github_url(package_info, name)
        if github_url is None:
            return False, "Could not find a GitHub URL in the package metadata"

        log.debug(f"Using GitHub URL {github_url}")

        # Step 2: Get version (ecosystem-specific)
        version = self.get_version(package_info, version)
        if version is None:
            return False, "Could not determine version to scan"

        # Step 3: Clone repository
        tmp_dir = os.path.dirname(path)
        repo_path = os.path.join(tmp_dir, "sources", name)

        try:
            repo = pygit2.clone_repository(url=github_url, path=repo_path)
        except Exception as e:
            return False, f"Could not clone repository: {str(e)}"

        # Step 4: Find matching git tag
        tag_candidates = self.find_suitable_tags(repo, version)
        if len(tag_candidates) == 0:
            return False, f"Could not find a tag matching version {version}"

        target_tag = tag_candidates[-1]

        # Step 5: Get base path where files are located (ecosystem-specific)
        try:
            base_path = self.get_base_path(path, name)
        except Exception as e:
            return False, f"Could not locate package files: {str(e)}"

        # Step 6: Compare files
        mismatch = self.find_mismatch_for_tag(repo, target_tag, base_path, repo_path)

        if len(mismatch) == 0:
            return False, ""

        # Step 7: Format result message
        message = "\n".join(map(lambda x: "* " + x["file"], mismatch))
        return (
            True,
            f"Files in package differ from GitHub repository for version {version}:\n{message}",
        )

    def find_suitable_tags(self, repo: str, version: str) -> list[str]:
        """
        Find git tags that match the given version.

        Args:
            repo: pygit2.Repository object
            version: version string to match

        Returns:
            List of tag references that match the version
        """
        tags_regex = re.compile("^refs/tags/(.*)")
        tags = []
        for ref in repo.references:
            match = tags_regex.match(ref)
            if match is not None:
                tags.append(match.group(0))

        tag_candidates = []
        for tag_name in tags:
            tag_ref = tag_name.rsplit("/", 1)[-1]
            if tag_ref == version or tag_ref == f"v{version}":
                tag_candidates.append(tag_name)
        return tag_candidates

    def exclude_result(
        self, file_name: str, repo_root: str = None, pkg_root: str = None
    ) -> bool:
        """
        Check if a file should be excluded from integrity checking.

        Args:
            file_name: name of the file to check
            repo_root: path to the repository directory (optional, for subclass-specific logic)
            pkg_root: path to the package directory (optional, for subclass-specific logic)

        Returns:
            True if the file should be excluded, False otherwise
        """
        for extension in self.EXCLUDED_EXTENSIONS:
            if file_name.endswith(extension):
                return True
        return False

    def find_mismatch_for_tag(
        self, repo, tag: str, base_path: str, repo_path: str
    ) -> list[dict]:
        """
        Find files that differ between the repository and the package.

        Args:
            repo: pygit2.Repository object
            tag: git tag reference to checkout
            base_path: path to the extracted package
            repo_path: path to the cloned repository

        Returns:
            List of dictionaries describing mismatched files
        """
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
                if self.exclude_result(file_name, repo_root, root):
                    continue
                repo_hash, _ = get_file_hash(os.path.join(repo_root, file_name))
                pkg_hash, _ = get_file_hash(os.path.join(root, file_name))
                if repo_hash != pkg_hash:
                    res = {
                        "file": os.path.join(relative_path, file_name),
                        "repo_sha256": repo_hash,
                        "pkg_sha256": pkg_hash,
                    }
                    mismatch.append(res)
        return mismatch
