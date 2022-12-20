""" Empty Information Detector

Detects if a package contains an empty description
"""
import configparser
import difflib
import hashlib
import os
import re
from typing import Optional, Set, Any

import pygit2
from semantic_version import Version

from guarddog.analyzer.metadata.repository_integrity_missmatch import IntegrityMissmatch

GH_REPO_REGEX = r'(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/){2}'
GH_REPO_OWNER_REGEX = r'(?:https?://)?(?:www\.)?github\.com/([\w-]+)/([\w-]+)'


# eventually, GuardDog core should be doing the job of selecting a single version to scan
def parse_version(raw):
    try:
        v = Version.coerce(raw)
        return {
            "version": v,
            "raw": raw
        }
    except Exception:
        return {
            "version": Version("0.0.0"),
            "raw": raw
        }


def find_version(package_info):
    all_versions = list(map(
        parse_version,
        list(package_info["releases"].keys())
    ))
    version = max(all_versions, key=lambda x: x["version"])
    return version["raw"]


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
        github_url = None
        for entry in github_urls:
            if f"/{name}" in entry:
                github_url = entry
                break

        if github_url is None:
            return False, "Could not find a good GitHub url in the project's description"

        # ok, now let's try to find the version! (I need to know which version we are scanning)
        if version is None:
            version = find_version(package_info)
        if version is None:
            raise Exception("Could not find suitable version to scan")
        tmp_dir = os.path.dirname(path)

        owner, repo = extract_owner_and_repo(github_url)
        if owner is None or repo is None:
            raise Exception(f"Could not parse url {github_url}")

        repo_path = os.path.join(tmp_dir, "sources", repo)
        repo = pygit2.clone_repository(url=f"https://github.com/{owner}/{repo}", path=repo_path)
        tags_regex = re.compile('^refs/tags/(.*)')
        tags = []
        for ref in repo.references:
            match = tags_regex.match(ref)
            if match is not None:
                tags.append(match.group(0))

        tag_candidates = []
        for tag_name in tags:
            if version in tag_name:
                tag_candidates.append(tag_name)

        # TODO: parse the code of the package to find the real real version Idea: we can grep the project files for
        #  the version, the, git biscect until we have a file with the same version? will not work if main has not
        #  been bumped yet in version so tags and releases are out only solutions here print(tag_candidates)
        #  Well, that works if we run integrity check for multiple commits

        #  should be good, but let's open the sources
        base_dir_name = None
        for entry in os.listdir(path):
            if entry.lower().startswith(name.lower()):
                base_dir_name = entry
        if base_dir_name is None or base_dir_name == "sources":  # I am not sure how we can get there
            raise Exception("something went wrong when opening the package")
        base_path = os.path.join(path, base_dir_name)

        if len(tag_candidates) == 0:
            return False, "Could not find any suitable tag in repository"

        target_tag = None
        # best candidate should have the closest
        for tag in tag_candidates:  # FIXME: for pyaml we scan 6.0 instead of 6.0b1 - there must be a way
            target_tag = tag

        missmatch = find_missmatch_for_tag(repo, target_tag, base_path, repo_path)
        message = "\n".join(map(
            lambda x: "* " + x["file"],
            missmatch
        ))
        return len(missmatch) > 0, f"Some files present in the package are different from the ones on GitHub for " \
                                   f"the same version of the package: \n{message}"
