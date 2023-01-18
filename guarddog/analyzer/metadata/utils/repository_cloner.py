import abc
import os
import re
from typing import Tuple, Optional

import pygit2
import urllib3

GH_REPO_REGEX = r'(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/)(?:[\w-]+)'
GH_REPO_OWNER_REGEX = r'(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)'


def ensure_proper_url(url):
    parsed = urllib3.util.parse_url(url)
    if parsed.scheme is None:
        url = f"https://{url}"
    return url


def extract_owner_and_repo(url) -> Tuple[Optional[str], Optional[str]]:
    match = re.search(GH_REPO_OWNER_REGEX, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        return owner, repo
    return None, None


class RepositoryCloner:

    def __init__(self, package_info, name) -> None:
        self.name = name
        self.package_info = package_info
        urls, preferred = self.find_repository_urls()
        self.urls = urls
        self.preferred = preferred

        self.clone_url = None
        self.clone_path = None
        self.clone_error = None
        self.pygit2_repo = None

    @abc.abstractmethod
    def find_repository_urls(self) -> Tuple[set[str], Optional[str]]:
        """
        Finds GitHub repository URLs based on package_infos
        If there is a preferred candidate identified as the repository URL by the metadata, it is returned as the
        second element of the tuple
        returns (list_of_candidates, preferred_candidate)
        """
        pass

    def find_best_github_candidate(self):
        """
        This method goes through multiple URLs and checks which one is the most suitable to be used as GitHub URL for
        the project repository.
        If the repository homepage is a GitHub URL, it is used in priority
        """
        if self.clone_url is not None:
            # we already have a target url
            return
        # if the project url is a GitHub repository, we should follow this as an instruction. Users will click on it
        if self.preferred is not None:
            best_github_candidate = self.preferred.replace("http://", "https://")
            url = urllib3.util.parse_url(best_github_candidate)
            if url.host == "github.com":
                self.clone_url = best_github_candidate
                return
        clean_candidates = []
        for entry in self.urls:
            # let's do some cleanup
            url = urllib3.util.parse_url(entry)
            if url.host != "github.com":
                continue
            if url.scheme == "http":
                entry = entry.replace("http://", "https://")
            clean_candidates.append(entry)
        for entry in clean_candidates:
            if f"/{self.name.lower()}" in entry.lower():
                self.clone_url = entry
                return
        # solution 1 did not work, let's be a bit more aggressive
        for entry in clean_candidates:
            owner, repo = extract_owner_and_repo(entry)
            if repo is not None and (
                    # Idea: replace by if two strings have a Levenshtein distance < X% of string length
                    repo.lower() in self.name.lower() or self.name.lower() in repo.lower()):
                self.clone_url = entry
                return

    def clone(self, package_path: str):
        # let's ensure we have a real url to clone here
        if self.pygit2_repo is not None or self.clone_error is not None:
            # we have already (attempted to) clone(d) this repo
            return
        if self.clone_url is None:
            self.find_best_github_candidate()
        if self.clone_url is None:
            return False
        base_clone_path = None
        if self.clone_path is None:
            base_clone_path = os.path.dirname(package_path)
        if base_clone_path is None:
            raise Exception("no current scanning directory")
        self.clone_path = os.path.join(base_clone_path, "sources", self.name)
        try:
            self.pygit2_repo = pygit2.clone_repository(url=self.clone_url, path=self.clone_path)
        except Exception as e:
            self.clone_error = e
