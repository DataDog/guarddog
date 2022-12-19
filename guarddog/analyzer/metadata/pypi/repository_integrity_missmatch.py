""" Empty Information Detector

Detects if a package contains an empty description
"""
import re
from typing import Optional

from guarddog.analyzer.metadata.repository_integrity_missmatch import IntegrityMissmatch


GH_REPO_REGEX = r'(?:https?://)?(?:www\.)?github\.com/(?:[\w-]+/){2}'


def find_repository_url(string):
    match = re.search(GH_REPO_REGEX, string)
    if match:
        return match.group(0)
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


class PypiIntegrityMissmatch(IntegrityMissmatch):
    """This package contains files that have been tampered with between the source repository and the package CDN"""
    RULE_NAME = "repository_integrity_missmatch"

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        # let's extract a source repository (GitHub only for now) if we can
        infos = package_info["info"]
        github_urls = set()
        for path in dict_generator(infos):
            leaf = path[-1]
            if type(leaf) is not str:
                continue
            res = re.findall(GH_REPO_REGEX, leaf)
            if len(res) > 0:
                for cd in res:
                    github_urls.add(cd.strip())

        if len(github_urls) == 0:
            return False, "Could not find any GitHub url in the project's description"
        # now

        # ok, now let's try to find the version! (I need to know which version we are scanning)
        # with a GH release/tag
        # by finding the commit setting the version
        # cool we have the version, let's compare files that exist

        return False, ""

# d = PypiIntegrityMissmatch()
# d.detect(FLASK_2_2_2_INFO, None)
