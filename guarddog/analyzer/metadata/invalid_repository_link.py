""" Empty Information Detector

Detects if a package contains an empty description
"""
from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector


class InvalidRepository(Detector):
    """This package refers to non-existing or private code repositories"""
    RULE_NAME = "invalid_repository_link"

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None, utils_bundle=None) -> tuple[bool, str]:
        # FIXME: this duplicates a lot of code from the integrity checks
        if name is None:
            raise Exception("Detector needs the name of the package")
        if path is None:
            raise Exception("Detector needs the path of the package")
        if utils_bundle is None or utils_bundle.repository_cloner is None:
            raise Exception("Detector needs a repository_cloner")

        cloner = utils_bundle.repository_cloner  # type: RepositoryCloner
        if len(cloner.urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        cloner.find_best_github_candidate()
        if cloner.clone_url is None:
            return False, "Could not find a good GitHub url in the project's description"

        if version is None:
            version = package_info["info"]["version"]
        if version is None:
            raise Exception("Could not find suitable version to scan")

        cloner.clone(path)
        if cloner.pygit2_repo is None:
            if cloner.clone_error is not None:
                return True, ""
            return True, ""
        return False, ""
