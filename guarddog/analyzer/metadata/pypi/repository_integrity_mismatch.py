"""Empty Information Detector

Detects if a package contains an empty description
"""

import configparser
import logging
import os
import re
import requests
from typing import Optional, Tuple


import pygit2  # type: ignore
import urllib3.util

from guarddog.analyzer.metadata.utils import get_file_hash
from guarddog.analyzer.metadata.repository_integrity_mismatch import IntegrityMismatch

GH_REPO_REGEX = r"(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/)(?:[\w-]+)"
GH_REPO_OWNER_REGEX = r"(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)"

log = logging.getLogger("guarddog")


def extract_owner_and_repo(url) -> Tuple[Optional[str], Optional[str]]:
    match = re.search(GH_REPO_OWNER_REGEX, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        return owner, repo
    return None, None


def find_best_github_candidate(all_candidates_and_highlighted_link, name):
    """
    This method goes through multiple URLs and checks which one is the most suitable to be used as GitHub URL for
    the project repository.
    If the repository homepage is a GitHub URL, it is used in priority
    """
    candidates, best_github_candidate = all_candidates_and_highlighted_link

    # if the project url is a GitHub repository, we should follow this as an instruction. Users will click on it
    if best_github_candidate is not None:
        best_github_candidate = best_github_candidate.replace("http://", "https://")
        url = urllib3.util.parse_url(best_github_candidate)
        if url.host == "github.com":
            return best_github_candidate
    clean_candidates = []
    for entry in candidates:
        # let's do some cleanup
        url = urllib3.util.parse_url(entry)
        if url.host != "github.com":
            continue
        if url.scheme == "http":
            entry = entry.replace("http://", "https://")
        clean_candidates.append(entry)
    for entry in clean_candidates:
        if f"/{name.lower()}" in entry.lower():
            return entry
    # solution 1 did not work, let's be a bit more aggressive
    for entry in clean_candidates:
        owner, repo = extract_owner_and_repo(entry)
        if repo is not None and (
            # Idea: replace by if two strings have a Levenshtein distance < X% of string length
            repo.lower() in name.lower()
            or name.lower() in repo.lower()
        ):
            return entry
    return None


def dict_generator(indict, pre=None):
    """
    This generator recursively go through an arbitrary dict
    Each iteration will be an array containing the path of all leaves of the dict
    """
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                for d in dict_generator(value, pre + [key]):
                    yield d
            elif isinstance(value, list) or isinstance(value, tuple):
                for v in value:
                    for d in dict_generator(v, pre + [key]):
                        yield d
            else:
                yield pre + [key, value]
    else:
        yield pre + [indict]



def _ensure_proper_url(url):
    parsed = urllib3.util.parse_url(url)
    if parsed.scheme is None:
        url = f"https://{url}"
    return url


def find_github_candidates(package_info) -> Tuple[set[str], Optional[str]]:
    infos = package_info["info"]
    homepage = None

    project_urls = infos.get("project_urls", {})

    # In some cases, the "project_urls" key is set, but is set to None
    if project_urls is None:
        return set(), None

    if "Homepage" in project_urls:
        homepage = package_info["info"]["project_urls"]["Homepage"]
    github_urls = set()
    for dict_path in dict_generator(infos):
        leaf = dict_path[-1]
        if type(leaf) is not str:
            continue
        res = re.findall(GH_REPO_REGEX, leaf)
        if len(res) > 0:
            for cd in res:
                github_urls.add(_ensure_proper_url(cd.strip()))
    best = None
    if homepage in github_urls:
        if homepage is not None and isinstance(homepage, str):
            response = requests.get(homepage)
            if response.status_code == 200:
                best = _ensure_proper_url(homepage)

    return github_urls, best





# Note: we should have the GitHub related logic factored out as we will need it when we check for signed commits
class PypiIntegrityMismatchDetector(IntegrityMismatch):
    """
    This heuristic compares source code available on the package source code repository (e.g. GitHub), and source code
    published on PyPI. If a file is on both sides but has a different content, this heuristic will flag the package.

    This helps identify packages whose release artifacts were modified directly on PyPI.

    Current gaps:
    * Does not check for extraneous files in the release artifacts
    * Does not run it parallel, so can be slow for large code bases
    """

    RULE_NAME = "repository_integrity_mismatch"
    EXCLUDED_EXTENSIONS = [".rst", ".md", ".txt"]

    def exclude_result(self, file_name: str, repo_root: str = None, pkg_root: str = None) -> bool:
        """
        Override base class method to add PyPI-specific exclusion logic.
        
        This method filters out some results that are known false positives:
        * if the file is a documentation file (based on its extension)
        * if the file is a setup.cfg file with the egg_info claim present on PyPI and not on GitHub
        """
        # First check standard extensions using base class logic
        if super().exclude_result(file_name, repo_root, pkg_root):
            return True
        
        # PyPI-specific: check for setup.cfg with egg_info differences
        if file_name.endswith("setup.cfg") and repo_root is not None and pkg_root is not None:
            repo_cfg = configparser.ConfigParser()
            repo_cfg.read(os.path.join(repo_root, file_name))
            pkg_cfg = configparser.ConfigParser()
            pkg_cfg.read(os.path.join(pkg_root, file_name))
            repo_sections = list(repo_cfg.keys())
            pkg_sections = list(pkg_cfg.keys())
            if "egg_info" in pkg_sections and "egg_info" not in repo_sections:
                return True
        return False

    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        if name is None:
            raise Exception("Detector needs the name of the package")
        if path is None:
            raise Exception("Detector needs the path of the package")

        log.debug(
            f"Running repository integrity mismatch heuristic on PyPI package {name} version {version}"
        )
        # let's extract a source repository (GitHub only for now) if we can
        github_urls, best_github_candidate = find_github_candidates(package_info)
        if len(github_urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        # now, let's find the right url

        github_url = find_best_github_candidate(
            (github_urls, best_github_candidate), name
        )

        if github_url is None:
            return (
                False,
                "Could not find a good GitHub url in the project's description",
            )

        log.debug(f"Using GitHub URL {github_url}")
        # ok, now let's try to find the version! (I need to know which version we are scanning)
        if version is None:
            version = package_info["info"]["version"]
        if version is None:
            raise Exception("Could not find suitable version to scan")
        tmp_dir = os.path.dirname(path)
        if tmp_dir is None:
            raise Exception("no current scanning directory")

        repo_path = os.path.join(tmp_dir, "sources", name)
        try:
            repo = pygit2.clone_repository(url=github_url, path=repo_path)
        except pygit2.GitError as git_error:
            # Handle generic Git-related errors
            raise Exception(
                f"Error while cloning repository {str(git_error)} with github url {github_url}"
            )
        except Exception as e:
            # Catch any other unexpected exceptions
            raise Exception(
                f"An unexpected error occurred: {str(e)}.  github url {github_url}"
            )

        tag_candidates = self.find_suitable_tags(repo, version)

        if len(tag_candidates) == 0:
            return False, "Could not find any suitable tag in repository"

        target_tag = tag_candidates[-1]

        # Idea: parse the code of the package to find the real version - we can grep the project files for
        #  the version, git bisect until we have a file with the same version? will not work if main has not
        #  been bumped yet in version so tags and releases are out only solutions here print(tag_candidates)
        #  Well, that works if we run integrity check for multiple commits

        #  should be good, let's open the sources
        base_dir_name = None
        for entry in os.listdir(path):
            if entry.lower().startswith(
                name.lower().replace("-", "_")
            ) or entry.lower().startswith(name.lower()):
                base_dir_name = entry
        if (
            base_dir_name is None or base_dir_name == "sources"
        ):  # I am not sure how we can get there
            raise Exception("something went wrong when opening the package")
        base_path = os.path.join(path, base_dir_name)

        mismatch = self.find_mismatch_for_tag(repo, target_tag, base_path, repo_path)
        message = "\n".join(map(lambda x: "* " + x["file"], mismatch))
        return (
            len(mismatch) > 0,
            f"Some files present in the package are different from the ones on GitHub for "
            f"the same version of the package: \n{message}",
        )