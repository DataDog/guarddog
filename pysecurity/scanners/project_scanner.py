import json
from posixpath import dirname
import time
import requests
from pysecurity.scanners.scanner import Scanner

BASE_URL = "https://api.github.com"
DATADOG_URL_SUFFIX = "orgs/DataDog/repos"
MAX_RESULTS_PER_PAGE = 100
SAVED_CACHE = dirname(__file__)

class RequirementsScanner(Scanner):
    def __init__(self) -> None:
        super(Scanner)

    
    def get_repos(self):
        print("Getting repos...")
        print("\n")
        all_repos = []
        page_id = 0
        results_count = MAX_RESULTS_PER_PAGE

        # TODO: Need to implement this from D's old PR to get private repos
        # pat_auth = authenticate_by_access_token()
        while (results_count == MAX_RESULTS_PER_PAGE):
            req_url = "{0}/{1}?per_page={2}&page={3}".format(BASE_URL, DATADOG_URL_SUFFIX, MAX_RESULTS_PER_PAGE, page_id)
            print("Query URL: ", req_url, " on page: ", page_id)
            resp = requests.get(url=req_url)

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
                
        for repo in all_repos:
            html_url = repo['html_url']
            default_branch = repo['default_branch']
            githubusercontent_url = html_url.replace("github", "raw.githubusercontent")
            
            req_url = f"{githubusercontent_url}/{default_branch}/requirements.txt"
            resp = requests.get(url=req_url)
            if resp.status_code == 200:
                # Read the requirements.txt file and output the dependencies and versions
                dependencies = self.read_response()
                
                # Next, open a thread for each of the dependencies
                for dependency in dependencies:
                    do_thing()
        
        return all_repos
    
    def read_response():
        raise NotImplemented

    
    def do_thing():
        raise NotImplemented
