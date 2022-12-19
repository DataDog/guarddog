""" Empty Information Detector

Detects if a package contains an empty description
"""
import hashlib
import os
import re
import subprocess
from typing import Optional

import requests

from guarddog.analyzer.metadata.repository_integrity_missmatch import IntegrityMissmatch

GH_REPO_REGEX = r'(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/){2}'
GH_REPO_OWNER_REGEX = r'(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)'


def extract_owner_and_repo(url):
    match = re.search(GH_REPO_OWNER_REGEX, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        return owner, repo
    return None, None


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
        hash_object = hashlib.sha1()
        # Feed the file contents to the hash object
        hash_object.update(file_contents)
        # Get the hexadecimal hash value
        return hash_object.hexdigest()

class PypiIntegrityMissmatch(IntegrityMissmatch):
    """This package contains files that have been tampered with between the source repository and the package CDN"""
    RULE_NAME = "repository_integrity_missmatch"

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        # let's extract a source repository (GitHub only for now) if we can
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

        if len(github_urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        # now, let's find the right url
        github_url = None
        for entry in github_urls:
            if f"/{name}" in entry:
                github_url = entry
                break

        if github_url is None:
            return False, "Could not find a good GitHub url in the project's description"

        # ok, now let's try to find the version! (I need to know which version we are scanning)
        if version is None:
            return False, ""  # FIXME: use latest come on!
        tmp_dir = os.path.dirname(path)

        owner, repo = extract_owner_and_repo(github_url)
        if owner is None or repo is None:
            raise Exception(f"Could not parse url {github_url}")

        tags_request = requests.get(f"https://api.github.com/repos/{owner}/{repo}/tags")
        if tags_request.status_code != 200:
            raise Exception(f"something went wrong when listing tags for repo {owner}/{repo}")
        tags = tags_request.json()
        tag_candidates = []
        for tag_info in tags:
            if version in tag_info["name"]:
                tag_candidates.append(tag_info)

        #  TODO: parse the code of the package to find the real real version
        # Idea: we can grep the project files for the version, the, git biscect until we have a file with the same version?
        # will not work if main has not been bumped yet in version
        # so tags and releases are out only solutions here
        # print(tag_candidates)

        target_tag = None
        for tag in tag_candidates:
            target_tag = tag

        if target_tag is None:
            return False, "Could not find a suitable tag on GitHub"

        repo_path = os.path.join(tmp_dir, "sources", repo)
        # Do we need to use pygit2 here instead? probably to reduce risks of code execution here
        subprocess.run(["git", "clone", "-b", target_tag["name"], f"https://github.com/{owner}/{repo}", repo_path])
        # with a GH release/tag
        # by finding the commit setting the version
        # cool we have the version, let's compare files that exist
        base_dir_name = os.listdir(path)[0]  #  FIXME!!
        base_path = os.path.join(path, base_dir_name)
        missmatches = set()
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
                if file_name not in files:
                    continue
                repo_hash = get_file_hash(os.path.join(repo_root, file_name))
                pkg_path = get_file_hash(os.path.join(root, file_name))
                if repo_hash != pkg_path:
                    missmatches.add(os.path.join(relative_path, file_name))
        missmatch_strings = ", ".join(missmatches)
        return len(missmatches) > 0, f"Some files present in the package are different from the ones on GitHub for " \
                                     f"the same version of the package. {missmatch_strings} "
