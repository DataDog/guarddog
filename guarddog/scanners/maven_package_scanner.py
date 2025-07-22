import logging
import os
import subprocess
import typing
import xml.etree.ElementTree as ET
import requests
import filecmp

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
        """
        Downloads the package from Maven Central (.jar)
        Downloads the corresponding pom file
        Decompressed the .jar
        Decompile the .jar
        Args:
            * `package_name` (str): group_id:artifact_id of the package on Maven
            * `version` (str): version of the package
            * `directory` (str): name of the dir to host the package. Created if does not exist
        Returns:
            * `package_info` (dict): necessary metadata for analysis
            * `path` (str): path to the local package:
                - pom.xml
                - decompressed/decompressed_jar
                - decompiled/decompiled_java_files
        """
        if version is None:
            raise ValueError("Version must be specified for Maven packages")
        try:
            group_id, artifact_id = package_name.split(":")
        except ValueError:
            raise Exception(
                f"Invalid package format: '{package_name}'. Expected 'groupId:artifactId'"
            )
        if not directory:
            directory = artifact_id

        jar_path, pom_path = self.download_package(
            group_id, artifact_id, directory, version
        )

        # decompress jar
        if is_supported_archive(jar_path):
            log.debug(f"Extracting {jar_path} into {directory}...")
            decompressed_path: str = os.path.join(directory, "decompressed")
            safe_extract(source_archive=jar_path, target_directory=decompressed_path)

        # decompile jar
        decompiled_path: str = os.path.join(directory, "decompiled")
        self.decompile_jar(jar_path, decompiled_path)

        # diff between retrieved and decompressed pom
        jar_pom: tuple[bool, str] | None = self.diff_pom(
            directory, group_id, artifact_id, pom_path
        )
        if jar_pom:
            same, pom_jar_path = jar_pom
            if same:
                log.debug("Same pom.xml in Maven and decompressed project!")
            else:
                print("The 2 found pom.xml for the project differ.")
                pom_path = pom_jar_path

        # analyse resulting files

    def download_package(
        self, group_id: str, artifact_id: str, directory: str, version: str
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

    def find_pom(self, path: str, groupId: str, artifactId: str) -> str | None:
        """
        Finds the pom.xml in the package at `path` if exists
        """
        pom_path = os.path.join(
            path, "META-INF", "maven", groupId, artifactId, "pom.xml"
        )
        if os.path.exists(pom_path):
            return pom_path
        else:
            print(f"No pom.xml found at {pom_path}")
            return None

    def diff_pom(
        self, path: str, groupId: str, artifactId: str, pom_path: str
    ) -> tuple[bool, str] | None:
        """
        Args
            - `path` (str): path to the decompressed project
            - `groupId` (str): groupid of the package
            - `artifactId` (str): artifact id of the package
            - `pom_path` (str): pom.xml path to compare the project pom to

        Compare both poms and returns a bool
        Returns:
            - True if same poms
            - False if not
            - If pom found, returns the pom path
        """
        if not os.path.exists(pom_path):
            return
        jar_pom = self.find_pom(path, groupId, artifactId)
        if jar_pom:
            return filecmp.cmp(jar_pom, pom_path), jar_pom
        else:
            return

    def decompile_jar(self, jar_path: str, dest_path: str, cfr_jar_path: str):
        """
        Decompiles the .jar file using CFR decompiler.
        Args:
            - `jar_path` (str): path of the .jar to decompile
            - `dest_path` (str): path of the destination folder
            to store the resulting .class files
            - `cfr_jar_path` (str): Path to cfr.jar decompiler
        """
        if not os.path.isfile(jar_path):
            raise FileNotFoundError(f"JAR file not found: {jar_path}")
        if not os.path.isfile(cfr_jar_path):
            raise FileNotFoundError(f"CFR decompiler not found: {cfr_jar_path}")

        os.makedirs(dest_path, exist_ok=True)

        command = [
            "java",
            "-jar",
            cfr_jar_path,
            jar_path,
            "--outputdir",
            dest_path,
            "--silent",
        ]

        try:
            subprocess.run(command, check=True)
            log.debug(f"Decompiled JAR written to: {os.path.abspath(dest_path)}")
        except subprocess.CalledProcessError as e:
            print(f"Error running CFR: {e}")
