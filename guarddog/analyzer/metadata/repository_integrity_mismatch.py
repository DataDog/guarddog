import os
import re
from abc import abstractmethod
from typing import List, Optional

from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.utils import get_file_hash


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
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        pass

    def find_suitable_tags(self, repo, version: str) -> List[str]:
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

    def exclude_result(self, file_name: str, repo_root: str = None, pkg_root: str = None) -> bool:
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
    ) -> List[dict]:
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