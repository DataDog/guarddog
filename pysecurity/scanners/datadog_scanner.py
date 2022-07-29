import json
import time
from posixpath import dirname

import requests

from pysecurity.scanners.scanner import Scanner

BASE_URL = "https://api.github.com"
DATADOG_URL_SUFFIX = "orgs/DataDog/repos"
MAX_RESULTS_PER_PAGE = 100
SAVED_CACHE = dirname(__file__)


class DatadogScanner(Scanner):
    def __init__(self) -> None:
        super(Scanner)


    def authenticate_by_access_token(self):
        user = os.getenv('GIT_USERNAME')
        personal_access_token = os.getenv('GH_TOKEN')
        if user == None or personal_access_token == None:
            print("WARNING: Please set GIT_USERNAME (Github handle) and GH_TOKEN (generate a personal access token in Github settings > developer) as environment variables before proceeding.")
            exit(1)
        return (user, personal_access_token)
    
    
    def get_repos(self):
        print("Getting repos...")
        print("\n")
        all_repos = []
        page_id = 0
        results_count = MAX_RESULTS_PER_PAGE
        
        pat_auth = self.authenticate_by_access_token()
        
        while (results_count == MAX_RESULTS_PER_PAGE):
            req_url = "{0}/{1}?per_page={2}&page={3}".format(BASE_URL, DATADOG_URL_SUFFIX, MAX_RESULTS_PER_PAGE, page_id)
            print("Query URL: ", req_url, " on page: ", page_id)
            resp = requests.get(url=req_url, auth=pat_auth)

            if resp.status_code != 200:
                print("Bad response from Github: {0} Please try again!".format(resp.text))
                exit(1)
                
            cur_repos_str = resp.content
            cur_repos = json.loads(cur_repos_str)
            results_count = len(cur_repos)
            all_repos.extend(cur_repos)
            page_id += 1
            time.sleep(1)
            
            if page_id > 1:
                break
        
        result = None
        for repo in all_repos:
            url = repo['html_url']
            branch = repo['default_branch']
            result = self.scan_repo(url, branch)
        
        return result