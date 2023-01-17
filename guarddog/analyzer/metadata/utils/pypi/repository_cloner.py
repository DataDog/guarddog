import re
from typing import Tuple, Optional

from guarddog.analyzer.metadata.utils.repository_cloner import RepositoryCloner, ensure_proper_url, GH_REPO_REGEX


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


class PypiRepositoryCloner(RepositoryCloner):

    def find_repository_urls(self, package_info) -> Tuple[set[str], Optional[str]]:
        infos = self.package_info["info"]
        homepage = None
        if "Homepage" in package_info["info"]["project_urls"]:
            homepage = package_info["info"]["project_urls"]["Homepage"]
        github_urls = set()
        for dict_path in dict_generator(infos):
            leaf = dict_path[-1]
            if type(leaf) is not str:
                continue
            res = re.findall(GH_REPO_REGEX, leaf)
            if len(res) > 0:
                for cd in res:
                    github_urls.add(ensure_proper_url(cd.strip()))
        best = None
        if homepage in github_urls:
            best = ensure_proper_url(homepage)
        return github_urls, best
