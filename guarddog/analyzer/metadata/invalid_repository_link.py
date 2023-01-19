""" Empty Information Detector

Detects if a package contains an empty description
"""
from abc import abstractmethod
from typing import Optional

from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.utils.repository_cloner import RepositoryCloner, ensure_cloner_use


class InvalidRepository(Detector):
    """This package refers to non-existing or private code repositories"""
    RULE_NAME = "invalid_repository_link"

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None, utils_bundle=None) -> tuple[bool, str]:
        # FIXME: this duplicates a lot of code from the integrity checks
        ensure_cloner_use(name, path, utils_bundle)

        cloner = utils_bundle.repository_cloner  # type: RepositoryCloner
        if len(cloner.urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        cloner.find_best_github_candidate()
        if cloner.clone_url is None:
            return False, "Could not find a good GitHub url in the project's description"

        cloner.clone(path)
        if cloner.pygit2_repo is None:
            if cloner.clone_error is not None:
                return True, f"Could not clone {cloner.clone_url} due to error {str(cloner.clone_error)}"
            return True, f"Could not clone {cloner.clone_url}"
        return False, ""
