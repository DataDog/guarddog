""" Compromised Email Detector

Detects if a maintainer's email domain has been compromised.
"""

import os
import sys
from datetime import date, datetime

import requests
from dateutil import parser
from dotenv import load_dotenv
from packaging import version

from pysecurity.analyzer.metadata.detector import Detector


class MissingEnvironmentVariable(Exception):
    pass


class CompromisedEmailDetector(Detector):
    def __init__(self) -> None:
        load_dotenv()
        
        self.whoisurl = "https://zozor54-whois-lookup-v1.p.rapidapi.com/"
        self.rapidapikey = os.getenv("RAPID_API_KEY", None)
        
        if self.rapidapikey is None:
            sys.stderr.write("Environment variable RAPID_API_KEY missing. Skipping compromised email rule.")
            
        super(Detector)
            
            
    def _get_domain_creation_date(self, email_domain) -> date:
        if self.rapidapikey is None:
            raise MissingEnvironmentVariable
        
        querystring = {"domain": email_domain, "format": "json"}

        headers = {
            "X-RapidAPI-Key": self.rapidapikey,
            "X-RapidAPI-Host": "zozor54-whois-lookup-v1.p.rapidapi.com"
        }

        domain_information = requests.get(self.whoisurl, headers=headers, params=querystring)
        
        if domain_information.status_code != 200:
            raise Exception(f"Error with API to get domain creation date. Received {domain_information.status_code}.")
        
        created_text = domain_information.json()["created"]
        creation_date = datetime.strptime(created_text, "%Y-%m-%d %H:%M:%S").date()
        
        return creation_date
    
    
    def _get_project_creation_date(self, releases) -> date:
        sorted_versions = sorted(releases.keys(), key=lambda r: version.parse(r), reverse=True)
        earlier_versions = sorted_versions[:-1]
        
        for early_version in earlier_versions:
            version_release = releases[early_version]
            
            if len(version_release) > 0: # if there's a distribution for the package
                upload_time_text = version_release[0]["upload_time_iso_8601"]
                creation_date = parser.isoparse(upload_time_text).date()
                
                return creation_date
    
    
    def is_email_compromised(self, package_info) -> bool:
        email_domain = package_info["info"]["author_email"].split("@")[-1]
        releases = package_info["releases"]
        
        project_date = self._get_project_creation_date(releases) 
        domain_date = self._get_domain_creation_date(email_domain)
        return project_date < domain_date
    
    
    def detect(self, package_info) -> bool:
        return self.is_email_compromised(package_info)

