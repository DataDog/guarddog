import logging
import os
import typing
import xml.etree.ElementTree as ET
import requests

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import safe_extract, is_supported_archive

log = logging.getLogger("guarddog")

MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"


class MavenPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.MAVEN))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")
        if not directory:
            directory = package_name.split(":")[-1]

        jar_path, pom_path = self.download_package(package_name, directory, version)
        # decompress jar
        if is_supported_archive(jar_path):
            log.debug(f"Extracting {jar_path} into {directory}...")
            safe_extract(source_archive=jar_path, target_directory=directory)
            os.remove(jar_path)
        # decompile jar
        # analyse resulting files

    def download_package(
        package_name: str, directory: str, version: str
    ) -> tuple[str, str]:
        """
        Downloads the Maven package .jar and pom for the specified version
        in directory
        Args:
            * `package_name` (str): group_id:artifact_id of the package on Maven
            * `version` (str): version of the package
            * `directory` (str): name of the dir to host the package. Created if does not exist
        Returns:
            Paths of the downloded jar file and the corresponding downloaded pom.xml
        """
        try:
            group_id, artifact_id = package_name.split(":")
        except ValueError:
            raise Exception(
                f"Invalid package format: '{package_name}'. Expected 'groupId:artifactId'"
            )

        group_path = group_id.replace(".", "/")

        # urls to download pom and jar
        base_url = f"{MAVEN_CENTRAL_BASE_URL}/{group_path}/{artifact_id}/{version}"
        jar_url = f"{base_url}/{artifact_id}-{version}.jar"
        pom_url = f"{base_url}/{artifact_id}-{version}.pom"

        # destination files
        os.makedirs(directory, exist_ok=True)
        jar_path = os.path.join(directory, f"{artifact_id}-{version}.jar")
        pom_path = os.path.join(directory, "pom.xml")

        # We could also use the dowload_decompressed method from scanner.py
        try:
            for url, path in [(jar_url, jar_path), (pom_url, pom_path)]:
                r = requests.get(url, stream=True)
                if r.status_code != 200:
                    raise Exception(
                        f"Failed to download Maven package from {url} (status {r.status_code})"
                    )
                with open(path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

            log.debug(f"Downloaded JAR to: {jar_path}")
            log.debug(f"Downloaded POM to: {pom_path}")
            return jar_path, pom_path

        except Exception as e:
            raise Exception(f"Error retrieving Maven package: {e}")
