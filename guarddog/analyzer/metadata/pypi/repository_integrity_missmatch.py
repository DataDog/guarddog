""" Empty Information Detector

Detects if a package contains an empty description
"""
import configparser
import hashlib
import os
import re
from typing import Optional, Tuple

import pygit2
import urllib3.util

from guarddog.analyzer.metadata.repository_integrity_missmatch import IntegrityMissmatch

GH_REPO_REGEX = r'(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/)(?:[\w-]+)'
GH_REPO_OWNER_REGEX = r'(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)'


def extract_owner_and_repo(url) -> Tuple[str, str]:
    match = re.search(GH_REPO_OWNER_REGEX, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        return owner, repo
    return None, None


def find_best_github_candidate(candidates, name):
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
        if repo is not None and (repo.lower() in name.lower() or name.lower() in repo.lower()):  # TODO: replace by if two strings have a Levenstein distance < X% of string length
            return entry
    return None


def dict_generator(indict, pre=None):
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


def get_file_hash(path):
    with open(path, 'rb') as f:
        # Read the contents of the file
        file_contents = f.read()
        # Create a hash object
        hash_object = hashlib.sha256()
        # Feed the file contents to the hash object
        hash_object.update(file_contents)
        # Get the hexadecimal hash value
        return hash_object.hexdigest(), str(file_contents).strip().splitlines()


def find_github_candidates(package_info) -> set[str]:
    infos = package_info["info"]
    github_urls = set()
    for dict_path in dict_generator(infos):
        leaf = dict_path[-1]
        if type(leaf) is not str:
            continue
        res = re.findall(GH_REPO_REGEX, leaf)
        if len(res) > 0:
            for cd in res:
                github_urls.add(cd.strip())
    return github_urls


def exclude_result(file_name, repo_root, pkg_root):
    if file_name.endswith('.rst') or file_name.endswith('.md'):
        return True
    if file_name.endswith("setup.cfg"):
        repo_cfg = configparser.ConfigParser()
        repo_cfg.read(os.path.join(repo_root, file_name))
        pkg_cfg = configparser.ConfigParser()
        pkg_cfg.read(os.path.join(pkg_root, file_name))
        repo_sections = list(repo_cfg.keys())
        pkg_sections = list(pkg_cfg.keys())
        if "egg_info" in pkg_sections and "egg_info" not in repo_sections:
            return True
    return False


def find_missmatch_for_tag(repo, tag, base_path, repo_path):
    repo.checkout(tag)
    missmatch = []
    for root, dirs, files in os.walk(base_path):
        relative_path = os.path.relpath(root, base_path)
        repo_root = os.path.join(repo_path, relative_path)
        if not os.path.exists(repo_root):
            continue
        repo_files = list(filter(
            lambda x: os.path.isfile(os.path.join(repo_root, x)),
            os.listdir(repo_root)
        ))
        for file_name in repo_files:
            if file_name not in files:  # ignore files we don't have in the distribution
                continue
            repo_hash, repo_content = get_file_hash(os.path.join(repo_root, file_name))
            pkg_hash, pkg_content = get_file_hash(os.path.join(root, file_name))
            if repo_hash != pkg_hash:
                if exclude_result(file_name, repo_root, root):
                    continue
                res = {
                    "file": os.path.join(relative_path, file_name),
                    "repo_sha256": repo_hash,
                    "pkg_sha256": pkg_hash
                }
                missmatch.append(res)
    return missmatch


def find_suitable_tags(repo, version):
    tags_regex = re.compile('^refs/tags/(.*)')
    tags = []
    for ref in repo.references:
        match = tags_regex.match(ref)
        if match is not None:
            tags.append(match.group(0))

    tag_candidates = []
    for tag_name in tags:
        if tag_name.endswith(version):
            tag_candidates.append(tag_name)
    return tag_candidates


# Note: we should have the GitHub related logic factored out as we will need it when we check for signed commits
class PypiIntegrityMissmatch(IntegrityMissmatch):
    """This package contains files that have been tampered with between the source repository and the package CDN"""
    RULE_NAME = "repository_integrity_missmatch"

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        # let's extract a source repository (GitHub only for now) if we can
        github_urls = find_github_candidates(package_info)
        if len(github_urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        # now, let's find the right url
        # TODO: if homepage is a github repo, let's use that directly
        github_url = find_best_github_candidate(github_urls, name)

        if github_url is None:
            return False, "Could not find a good GitHub url in the project's description"

        # ok, now let's try to find the version! (I need to know which version we are scanning)
        if version is None:
            version = package_info["info"]["version"]
        if version is None:
            raise Exception("Could not find suitable version to scan")
        tmp_dir = os.path.dirname(path)

        repo_path = os.path.join(tmp_dir, "sources", name)
        repo = pygit2.clone_repository(url=github_url, path=repo_path)

        tag_candidates = find_suitable_tags(repo, version)

        if len(tag_candidates) == 0:
            return False, "Could not find any suitable tag in repository"

        target_tag = None
        # TODO: this one is a bit weak. let's find something stronger - maybe use the closest string?
        for tag in tag_candidates:
            target_tag = tag

        # Idea: parse the code of the package to find the real version - we can grep the project files for
        #  the version, the, git biscect until we have a file with the same version? will not work if main has not
        #  been bumped yet in version so tags and releases are out only solutions here print(tag_candidates)
        #  Well, that works if we run integrity check for multiple commits

        #  should be good, let's open the sources
        base_dir_name = None
        for entry in os.listdir(path):
            if entry.lower().startswith(name.lower()):
                base_dir_name = entry
        if base_dir_name is None or base_dir_name == "sources":  # I am not sure how we can get there
            raise Exception("something went wrong when opening the package")
        base_path = os.path.join(path, base_dir_name)

        missmatch = find_missmatch_for_tag(repo, target_tag, base_path, repo_path)
        message = "\n".join(map(
            lambda x: "* " + x["file"],
            missmatch
        ))
        return len(missmatch) > 0, f"Some files present in the package are different from the ones on GitHub for " \
                                   f"the same version of the package: \n{message}"
