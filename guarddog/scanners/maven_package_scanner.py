import logging
import os
import subprocess
import typing
import xml.etree.ElementTree as ET
import requests
import filecmp
import zipfile

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner

log = logging.getLogger("guarddog")

MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"
CFR_JAR_PATH = "../cfr-0.152.jar"


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
            * package_info (dict): necessary metadata for analysis
                - `path` (str): path to the local package:
                    - pom.xml
                    - decompressed/decompressed_jar
                    - decompiled/decompiled_java_files
            * path to the decompiled sourcecode
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
        decompressed_path: str = ""
        if jar_path.endswith(".jar"):
            log.debug(f"Extracting {jar_path} into {directory}...")
            decompressed_path = os.path.join(directory, "decompressed")
            self.extract_jar(jar_path, decompressed_path)
        else:
            log.debug(f"Could not extract {jar_path}")
        if os.path.exists(decompressed_path) and os.path.getsize(decompressed_path) > 0:
            log.debug(f"Successfully extracted jar in {decompressed_path}.")
        else:
            log.error(f"The project could not be extracted from {jar_path}")

        # decompile jar
        decompiled_path: str = os.path.join(directory, "decompiled")
        self.decompile_jar(jar_path, decompiled_path)

        # diff between retrieved and decompressed pom
        jar_pom: tuple[bool, str] | None = self.diff_pom(
            decompressed_path, group_id, artifact_id, pom_path
        )
        if jar_pom:
            same, pom_jar_path = jar_pom
            if same:
                log.debug("Same pom.xml in Maven and decompressed project!")
            else:
                print("The 2 found pom.xml for the project differ.")
                print(f"\t -pom retrived from Maven: {pom_path}")
                print(f"\t -pom found in decompressed package: {pom_jar_path}")
                pom_path = pom_jar_path

        # package_info
        package_info: dict = self.get_package_info(
            pom_path, decompressed_path, decompiled_path, group_id, artifact_id, version
        )
        log.debug(f"Package info: {package_info}")
        return package_info, directory

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
        log.debug(f"Downloading package in {directory} ")
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

    def extract_jar(self, jar_path: str, output_dir: str):
        """
        Extract a jar archive file with zipfile
        - `jar_path` (str): path to the jar to extract
        - `output_dir` (str): directory to decompress the jar to
        """
        with zipfile.ZipFile(jar_path, "r") as jar:
            log.debug("Extracting jar package...")
            for file in jar.namelist():
                safe_path = os.path.join(output_dir, file)
                if file.endswith("/"):  # It's a directory
                    os.makedirs(safe_path, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                with open(safe_path, "wb") as f:
                    f.write(jar.read(file))
        log.debug(f"extracted to {output_dir}")

    def find_pom(self, path: str, groupId: str, artifactId: str) -> str | None:
        """
        Finds the pom.xml in the package at `path` if exists
        """
        pom_dir = os.path.join(path, "META-INF", "maven", groupId, artifactId)
        log.debug(f"Looking for pom.xml in {os.listdir(pom_dir)}")
        pom_path = os.path.join(pom_dir, "pom.xml")
        if os.path.isfile(pom_path):
            log.debug(f"Found pom.xml in decompressed project: {pom_path}")
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
            return None
        jar_pom = self.find_pom(path, groupId, artifactId)
        if jar_pom:
            return filecmp.cmp(jar_pom, pom_path), jar_pom
        else:
            return None

    def decompile_jar(self, jar_path: str, dest_path: str):
        """
        Decompiles the .jar file using CFR decompiler.
        Args:
            - `jar_path` (str): path of the .jar to decompile
            - `dest_path` (str): path of the destination folder
            to store the resulting .class files
        """
        if not os.path.isfile(jar_path):
            raise FileNotFoundError(f"JAR file not found: {jar_path}")
        if not os.path.isfile(CFR_JAR_PATH):
            raise FileNotFoundError(f"CFR jar file not found: {CFR_JAR_PATH}")

        os.makedirs(dest_path, exist_ok=True)

        command = [
            "java",
            "-jar",
            CFR_JAR_PATH,
            jar_path,
            "--outputdir",
            dest_path,
            "--silent",
            "true",
        ]

        try:
            subprocess.run(command, check=True)
            log.debug(f"Decompiled JAR written to: {os.path.abspath(dest_path)}")
        except subprocess.CalledProcessError as e:
            print(f"Error running CFR: {e}")

    def get_package_info(
        self,
        pom_path: str,
        decompressed_path: str,
        decompiled_path: str,
        group_id: str,
        artifact_id: str,
        version: str,
    ) -> dict:
        """
        Returns a dict with package info from args and retrived from parsing pom.xml
        "info"
            - "groupid"
            - "artifactid"
            - "version"
            - "email": list[str]
        "path"
            - "pom_path"
            - "decompressed_path"
            - "decompiled_path"
        """
        emails = []
        log.debug(f"Parsing pom {pom_path}")
        if not os.path.isfile(pom_path):
            log.warning(f"WARNING: {pom_path} does not exist.")
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Detect namespace if present
            namespace = ""
            if "}" in root.tag:
                namespace = root.tag.split("}")[0].strip("{")
            ns = {"mvn": namespace} if namespace else {}

            for dev in root.findall(".//mvn:developer", ns):
                email = dev.find("mvn:email", ns)
                if email is not None and email.text:
                    emails.append(email.text.strip())
            if not emails:
                log.debug("No email found in the pom.")

        except ET.ParseError as e:
            log.warning(f"Failed to parse POM: {pom_path}, error: {e}")
        except Exception as e:
            log.warning(f"Unexpected error parsing POM: {e}")

        return {
            "info": {
                "groupid": group_id,
                "artifactid": artifact_id,
                "version": version,
                "email": emails,
            },
            "path": {
                "pom_path": pom_path,
                "decompressed_path": decompressed_path,
                "decompiled_path": decompiled_path,
            },
        }
