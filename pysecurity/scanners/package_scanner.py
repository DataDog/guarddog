import json
import os
import shutil
import sys
import tempfile

import requests

from pysecurity.analyzer.analyzer import Analyzer
from pysecurity.scanners.scanner import Scanner


class PackageScanner(Scanner):
    def __init__(self) -> None:
        self.analyzer = Analyzer()
        super(Scanner)


    def scan_local(self, path, rules=None) -> dict:
        if rules is not None:
            rules = set(rules)
        
        if os.path.exists(path):
            return self.analyzer.analyze_sourcecode(path, rules=rules)
        else:
            raise Exception(f"Path {path} does not exist.")
    

    def scan_remote(self, name, version=None, rules=None):
        try:
            with tempfile.TemporaryDirectory() as tmpdirname:
                # Directory to download compressed and uncompressed package
                directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), tmpdirname)
                file_path = os.path.join(directory, name)
                
                self.download_package(name, directory, version)
                
                package_info = self.get_package_info(name)["info"]
                
                results = self.analyzer.analyze(file_path, package_info, rules)
                
                return results
        except Exception as e:
            sys.stderr.write("\n")
            sys.stderr.write(str(e))
            sys.exit()


    def download_package(self, package_name, directory, version=None) -> None:
        """Downloads the PyPI distribution for a given package and version

        Args:
            package_name (str): name of the package
            directory (str): directory to download package to
            version (str): version of the package

        Raises:
            Exception: "Received status code: " + <not 200> + " from PyPI"
            Exception: "Version " + version + " for package " + package_name + " doesn't exist."
            Exception: "Compressed file for package does not exist."
            Exception: "Error retrieving package: " + <error message>
        Returns:
            None
        """
        
        data = self.get_package_info(package_name)
        releases = data["releases"]
        
        if version is None:
            version = data['info']['version']
        
        if version in releases:
            files = releases[version]
            
            url = None
            file_extension = None
            
            for file in files:
                # Store url to compressed package and appropriate file extension
                if file["filename"].endswith(".tar.gz"):
                    url = file["url"]
                    file_extension = ".tar.gz"
                    
                if (file["filename"].endswith(".egg") or 
                    file["filename"].endswith(".whl") or 
                    file["filename"].endswith(".zip")):
                        url = file["url"]
                        file_extension = ".zip"
            
            if url and file_extension:          
                # Path to compressed package
                zippath = os.path.join(directory, package_name + file_extension) 
                unzippedpath = zippath.removesuffix(file_extension)
                
                self.download_compressed(url, zippath, unzippedpath)
            else:
                raise Exception(f"Compressed file for {package_name} does not exist on PyPI.")
        else:
            raise Exception(
                "Version " + version + " for package " + package_name + " doesn't exist."
            )
    
    
    def download_compressed(self, url, zippath, unzippedpath):
        """ Downloads a compressed file and extracts it

        Args:
            url (str): download link
            zippath (str): path to download compressed file
            unzippedpath (str): path to unzip compressed file
        """
        
        response = requests.get(url, stream=True)
        
        with open(zippath, "wb") as f:
            f.write(response.raw.read())
        
        shutil.unpack_archive(zippath, unzippedpath)
        os.remove(zippath)
        
    
    def get_package_info(self, name) -> json:
        """ Gets metadata and other information about package

        Args:
            name (str): name of the package

        Raises:
            Exception: "Received status code: " + str(response.status_code) + " from PyPI"
            Exception: "Error retrieving package: " + data["message"]

        Returns:
            json: package attributes and values
        """
        
        url = "https://pypi.org/pypi/%s/json" % (name,)
        response = requests.get(url)
        
        # Check if package file exists
        if response.status_code != 200:
            raise Exception("Received status code: " + str(response.status_code) + " from PyPI")
        
        data = response.json()
        
        # Check for error in retrieving package
        if "message" in data:
            raise Exception("Error retrieving package: " + data["message"])
        
        return data