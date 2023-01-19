""" Empty Information Detector

Detects if a package contains an empty description
"""
import configparser
import hashlib
import os
import re
from typing import Optional, Tuple

import pygit2  # type: ignore

from guarddog.analyzer.metadata.repository_integrity_mismatch import IntegrityMismatch
from guarddog.analyzer.metadata.utils.repository_cloner import RepositoryCloner, ensure_cloner_use


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


EXCLUDED_EXTENSIONS = [".rst", ".md", ".txt"]


def exclude_result(file_name, repo_root, pkg_root):
    """
    This method filters out some results that are known false positives:
    * if the file is a documentation file (based on its extension)
    * if the fil is an setup.cfg file with the egg_info claim present on Pypi and not on GitHub
    """
    for extension in EXCLUDED_EXTENSIONS:
        if file_name.endswith(extension):
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


def find_mismatch_for_tag(repo, tag, base_path, repo_path):
    repo.checkout(tag)
    mismatch = []
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
                mismatch.append(res)
    return mismatch


def find_suitable_tags_in_list(tags, version):
    tag_candidates = []
    for tag_name in tags:
        if tag_name.endswith(version):
            tag_candidates.append(tag_name)
    return tag_candidates


def find_suitable_tags(repo, version):
    tags_regex = re.compile('^refs/tags/(.*)')
    tags = []
    for ref in repo.references:
        match = tags_regex.match(ref)
        if match is not None:
            tags.append(match.group(0))

    return find_suitable_tags_in_list(tags, version)


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

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None, utils_bundle=None) -> tuple[bool, str]:
        ensure_cloner_use(name, path, utils_bundle)

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
                raise Exception('Something went wrong when cloning Git repository') from cloner.clone_error
            raise Exception('Something went wrong when cloning Git repository')

        tag_candidates = find_suitable_tags(cloner.pygit2_repo, version)

        if len(tag_candidates) == 0:
            return False, "Could not find any suitable tag in repository"

        target_tag = None
        # TODO: this one is a bit weak. let's find something stronger - maybe use the closest string?
        for tag in tag_candidates:
            target_tag = tag

        # Idea: parse the code of the package to find the real version - we can grep the project files for
        #  the version, git biscect until we have a file with the same version? will not work if main has not
        #  been bumped yet in version so tags and releases are out only solutions here print(tag_candidates)
        #  Well, that works if we run integrity check for multiple commits

        #  should be good, let's open the sources
        base_dir_name = None
        for entry in os.listdir(path):
            if entry.lower().startswith(name.lower().replace('-', '_')) or entry.lower().startswith(name.lower()):
                base_dir_name = entry
        if base_dir_name is None or base_dir_name == "sources":  # I am not sure how we can get there
            raise Exception("something went wrong when opening the package")
        base_path = os.path.join(path, base_dir_name)

        mismatch = find_mismatch_for_tag(cloner.pygit2_repo, target_tag, base_path, cloner.clone_path)
        message = "\n".join(map(
            lambda x: "* " + x["file"],
            mismatch
        ))
        return len(mismatch) > 0, f"Some files present in the package are different from the ones on GitHub for " \
                                  f"the same version of the package: \n{message}"
