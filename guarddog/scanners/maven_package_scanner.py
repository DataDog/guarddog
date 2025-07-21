import logging
import os
import typing
import xml.etree.ElementTree as ET
import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import safe_extract

log = logging.getLogger("guarddog")

MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"


class MavenPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.MAVEN))

    def _get_path_for_artifact(self, package_name: str, version: str, classifier: typing.Optional[str] = None,
                               extension: str = "jar") -> str:
        group_id, artifact_id = package_name.split(":")
        group_path = group_id.replace(".", "/")
        artifact_path = os.path.join(group_path, artifact_id, version)

        file_name = f"{artifact_id}-{version}"
        if classifier:
            file_name += f"-{classifier}"
        file_name += f".{extension}"

        return os.path.join(artifact_path, file_name)

    def _get_maven_central_url(self, package_name: str, version: str, classifier: typing.Optional[str] = None,
                               extension: str = "jar") -> str:
        """Get the Maven Central URL for an artifact"""
        artifact_path = self._get_path_for_artifact(package_name, version, classifier, extension)
        return f"{MAVEN_CENTRAL_BASE_URL}/{artifact_path}"

    def _parse_pom(self, pom_path: str) -> dict:
        try:
            tree = ET.parse(pom_path)
        except ET.ParseError as e:
            log.warning(f"Could not parse pom.xml at {pom_path}: {e}")
            return {}

        root = tree.getroot()

        namespace = ""
        if '}' in root.tag:
            namespace = root.tag.split('}')[0].strip('{')

        def find_text(elem, tag):
            ns_tag = f"{{{namespace}}}{tag}" if namespace else tag
            found = elem.find(ns_tag)
            return found.text if found is not None else None

        group_id = find_text(root, "groupId")
        artifact_id = find_text(root, "artifactId")
        version = find_text(root, "version")

        parent = root.find(f"{{{namespace}}}parent" if namespace else "parent")
        if parent is not None:
            if not group_id:
                group_id = find_text(parent, "groupId")
            if not version:
                version = find_text(parent, "version")

        if not artifact_id:
            log.warning(f"Could not extract artifactId from {pom_path}")

        name = f"{group_id}:{artifact_id}" if group_id and artifact_id else (artifact_id or "unknown")

        return {
            "info": {
                "name": name,
                "version": version or "unknown"
            }
        }

    def download_package(self, package_name: str, directory: str, version: typing.Optional[str] = None) -> str:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")

        _, artifact_id = package_name.split(":")

        sources_url = self._get_maven_central_url(package_name, version, classifier="sources", extension="jar")
        regular_url = self._get_maven_central_url(package_name, version, classifier=None, extension="jar")

        jar_to_download = None
        jar_type = None

        log.debug(f"Trying to download sources JAR from {sources_url}")
        response = requests.head(sources_url)
        if response.status_code == 200:
            jar_to_download = sources_url
            jar_type = "sources"
            log.debug(f"Found sources JAR for {package_name}:{version}")
        else:
            log.debug(f"Sources JAR not found, trying regular JAR from {regular_url}")
            response = requests.head(regular_url)
            if response.status_code == 200:
                jar_to_download = regular_url
                jar_type = "regular"
                log.debug(f"Found regular JAR for {package_name}:{version}")
            else:
                raise FileNotFoundError(f"Could not find JAR for {package_name}:{version} on Maven Central. "
                                        f"Checked sources at {sources_url} and regular at {regular_url}")

        destination_jar = os.path.join(directory, f"{artifact_id}-{version}-{jar_type}.jar")
        log.debug(f"Downloading JAR from {jar_to_download} to {destination_jar}")
        
        response = requests.get(jar_to_download, stream=True)
        response.raise_for_status()
        
        with open(destination_jar, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        unzippedpath = os.path.join(directory, package_name.replace(":", "_"))
        safe_extract(destination_jar, unzippedpath)
        return unzippedpath

    def download_and_get_package_info(self, directory: str, package_name: str,
                                      version: typing.Optional[str] = None) -> typing.Tuple[dict, str]:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")

        extract_dir = self.download_package(package_name, directory, version)

        pom_url = self._get_maven_central_url(package_name, version, classifier=None, extension="pom")
        pom_path = os.path.join(directory, f"{package_name.replace(':', '_')}.pom")
        
        log.debug(f"Downloading POM from {pom_url} to {pom_path}")
        response = requests.get(pom_url)
        if response.status_code != 200:
            raise FileNotFoundError(f"Could not find POM for {package_name}:{version} on Maven Central. "
                                    f"URL: {pom_url}")

        with open(pom_path, "w", encoding="utf-8") as f:
            f.write(response.text)

        package_info = self._parse_pom(pom_path)
        package_info.setdefault("info", {})["version"] = version

        return package_info, extract_dir
