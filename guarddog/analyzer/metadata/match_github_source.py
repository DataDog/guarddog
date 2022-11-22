"""Match Github Source

Does the build artifact (.tar.gz) listed on pypi match the build artifact of the same release for the project on Github? 
"""
from guarddog.analyzer.metadata.detector import Detector
from urllib.parse import urlparse, urlunparse
import hashlib
import json
import os
import requests
import re
import tempfile

class MatchGithubSource(Detector):
    """
    Detector for any differences between the build artifact listed on the pypi website and that of the package's corresponding Github release
    
    Args:
        Detector (_type_): Detector class defined in guarddog.analyzer.metadata.detector
    
    Raises:


    Returns:
    """

    def __init__(self) -> None:
        super()
        self.username = os.system('git config --global user.name')
        self.token = os.getenv('GIT_PAT_TOKEN')
    
    def detect(self, package_info) -> tuple[bool, str]:
        if self.token == "":
            raise Exception("cannot match pypi releases with source release code: no Github personal token provided as environment variable 'GIT_PAT_TOKEN'")
        
        elif self.username == "":
            raise Exception("cannot match pypi releases with source release code: no Github username provided in the global git config")

        home_page = package_info["info"]["home_page"]
        nested_home_page = package_info["info"]["project_urls"]["Homepage"]
        if home_page != "":
            try:
                u = urlparse(home_page)
                if u.hostname == "github.com":
                    releases = _get_git_builds(home_page, "releases", self.username, self.token)
                    if len(releases) > 0:
                        _match_releases(pypireleases= package_info['releases'], githubreleases=releases, username=self.username, token=self.token)
                    else:
                        tags = _get_git_builds(home_page, "tags", self.username, self.token)
                        if len(tags) > 0:
                            _match_releases(pypireleases= package_info['releases'], githubreleases=tags, username=self.username, token=self.token)
                else: 
                    return [False, 'project not hosted on Github'] #TODO: return proper error
            except Exception as e:
                raise Exception(f"error parsing package_info for homepage url: {e}")
        elif nested_home_page != "":
            try:
                u = urlparse(nested_home_page)
                if u.hostname == "github.com":
                    releases = _get_git_builds(nested_home_page, "releases", self.username, self.token)
                    if len(releases) > 0:
                        _match_releases(pypireleases= package_info['releases'], githubreleases=releases, username=self.username, token=self.token)
                    else:
                        tags = _get_git_builds(nested_home_page, "tags", self.username, self.token)
                else: 
                    return [False, 'project not hosted on Github'] #TODO: return proper error
            except Exception as e:
                raise Exception(f"error parsing package_info for nested homepage url: {e}") 
        else: #TODO: return proper error
            return [False, "error"]         
        return [False, "ok"]

def _get_git_builds(url: str, endpoint: str, username: str, token: str) -> dict: #TODO: separate out logic for auth to helper function for PAT and github action options
    # https://docs.github.com/en/rest/releases/releases
    # https://docs.github.com/en/rest/repos/repos#list-repository-tags

    #TODO:  validate endpoint as releases or tags
    u = urlparse(url)
    api_host = "api.github.com/repos"
    path = u.path.split("/")
    path.append(endpoint)
    path_with_releases = "/".join(path)

    new_url = urlunparse([u.scheme, api_host, path_with_releases, "", "", ""])

    r = requests.get(url=new_url, auth=(username, token)).json() #TODO: CHECK TAG RETURN FORMAT

    releases = {}

    if len(r) != 0:
        for release in r:
            version = release['name']
            if version.find("v") == 0:
                releases[version[1:]] = release['tarball_url']

    return releases

def _match_releases(pypireleases: dict, githubreleases: dict, username: str, token: str) -> tuple[bool, str]:
     res = {}
     for release, r_formats in pypireleases.items():
        for r in r_formats: 
            if r['packagetype'] == "sdist":
                pypi_digest = r['digests']['sha256']
                github_tar_url =  githubreleases[release]
                github_digest = _get_digest_from_url(github_url=github_tar_url, username=username, token=token)
                
                #print(f"pypi digest is {pypi_digest} from {pypi_tar_url}, github digest is {github_digest} from {github_tar_url}")
                if pypi_digest == github_digest:
                    res[release] = (True, "")
                else:
                    res[release] = (False, "releases do not match! D:")

def _get_digest_from_url(github_url: str, username: str, token: str) -> bool:    
    g = urlparse(github_url)
    if g.scheme != "https" or g.hostname != "api.github.com":
        raise Exception("malformed github url")
    
    zip_r = requests.get(url=github_url, auth=(username, token))
    
    github_checksum = _calculate_checksum(bytes(zip_r.text, 'utf-8'))

    return github_checksum

def _calculate_checksum(tar: bytes) -> int:
    try:
        h = hashlib.sha256()
        h.update(tar)
        return h.hexdigest()
    except Exception as e:
        raise(e)