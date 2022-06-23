import argparse
import tempfile
import os
import shutil
import requests
import tarfile

from semgrep.semgrep_main import invoke_semgrep
from pathlib import Path

cwd = os.getcwd()
parser = argparse.ArgumentParser()

parser.add_argument("-n", "--name", help="Package name", type=str, required=True)
parser.add_argument("-v", "--version", help="Package version", required=True)
parser.add_argument("-r", "--rules", help="Scanning heuristics", nargs="+", required=True)

args = parser.parse_args()


def get_package_urls(package_name, version):
    """_summary_

    Args:
        package_name (_type_): _description_
        version (_type_): _description_

    Raises:
        Exception: _description_

    Returns:
        _type_: _description_
    """
    
    url = "https://pypi.org/pypi/%s/json" % (package_name,)
    data = requests.get(url).json()
    releases = data["releases"]
    
    if version in releases:
        files = releases[version]
        urls = []
        
        for file in files:
            if file["filename"].endswith(".tar.gz"):
                urls.append(file["url"])
                
        return urls
    
    else:
        raise Exception("Version " + version + " for package " + package_name + " doesn't exist.")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdirname:
        package_urls = get_package_urls(args.name, args.version)
        package_url = package_urls[0]
        response = requests.get(package_url, stream=True)
        
        if response.status_code == 200:
            filename = tmpdirname + "/" + args.name + "-" + args.version
            
            with open(filename +  ".tar.gz", 'wb') as f:
                f.write(response.raw.read())
            
            file = tarfile.open(filename + ".tar.gz")
            file.extractall(filename)
            file.close()
            
            print(invoke_semgrep(Path("rules/semgrep"), [Path(filename)]))
        else:
            raise Exception("Received: " + response.status_code)

