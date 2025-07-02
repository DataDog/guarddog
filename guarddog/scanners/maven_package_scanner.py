import logging
import os
import shutil
import typing
import xml.etree.ElementTree as ET

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import safe_extract

log = logging.getLogger("guarddog")


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

        # Inherit from parent
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

    def _has_java_source_files(self, directory: str) -> bool:
        """Check if directory contains Java source files directly"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.java'):
                    return True
        return False

    def download_package(self, package_name: str, directory: str, version: typing.Optional[str] = None) -> str:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")

        local_maven_repo = os.path.expanduser("~/.m2/repository")
        _, artifact_id = package_name.split(":")
        
        # Try sources JAR first
        sources_path_in_repo = self._get_path_for_artifact(package_name, version, classifier="sources", extension="jar")
        full_sources_path = os.path.join(local_maven_repo, sources_path_in_repo)
        
        jar_to_extract = None
        jar_type = None
        
        if os.path.exists(full_sources_path):
            jar_to_extract = full_sources_path
            jar_type = "sources"
            log.debug(f"Found sources JAR for {package_name}:{version}")
        else:
            # Fallback to regular JAR
            regular_path_in_repo = self._get_path_for_artifact(package_name, version, classifier=None, extension="jar")
            full_regular_path = os.path.join(local_maven_repo, regular_path_in_repo)
            
            if os.path.exists(full_regular_path):
                jar_to_extract = full_regular_path
                jar_type = "regular"
                log.debug(f"Found regular JAR for {package_name}:{version} (sources not available)")
            else:
                raise FileNotFoundError(f"Could not find JAR for {package_name}:{version} in local Maven repository. "
                                      f"Looked for sources at {full_sources_path} and regular at {full_regular_path}")

        # Copy and extract the JAR
        destination_jar = os.path.join(directory, f"{artifact_id}-{version}-{jar_type}.jar")
        shutil.copyfile(jar_to_extract, destination_jar)

        unzippedpath = os.path.join(directory, package_name.replace(":", "_"))
        safe_extract(destination_jar, unzippedpath)
        return unzippedpath

    def download_and_get_package_info(self, directory: str, package_name: str,
                                      version: typing.Optional[str] = None) -> typing.Tuple[dict, str]:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")

        extract_dir = self.download_package(package_name, directory, version)

        local_maven_repo = os.path.expanduser("~/.m2/repository")
        pom_path_in_repo = self._get_path_for_artifact(package_name, version, classifier=None, extension="pom")
        full_pom_path = os.path.join(local_maven_repo, pom_path_in_repo)

        if not os.path.exists(full_pom_path):
            raise FileNotFoundError(f"Could not find pom for {package_name}:{version} in local Maven repository. "
                                  f"Looked for {full_pom_path}")

        package_info = self._parse_pom(full_pom_path)
        package_info.setdefault("info", {})["version"] = version

        return package_info, extract_dir

    def get_local_package_info(self, path: str) -> tuple[dict, str]:
        """
        Handle two modes:
        1. Directory with pom.xml and Java source files directly
        2. Directory containing a JAR file to extract
        """
        # Mode 1: Directory with Java source files and pom.xml
        pom_path = os.path.join(path, "pom.xml")
        if os.path.exists(pom_path) and self._has_java_source_files(path):
            log.debug(f"Found Java source files directly in {path}")
            package_info = self._parse_pom(pom_path)
            return package_info, path
        
        # Mode 2: Directory contains a JAR file
        jar_files = [f for f in os.listdir(path) if f.endswith('.jar')]
        if jar_files:
            # Use the first JAR file found
            jar_file = jar_files[0]
            jar_path = os.path.join(path, jar_file)
            
            # Extract to a subdirectory
            extract_dir = os.path.join(path, "extracted")
            if not os.path.exists(extract_dir):
                os.makedirs(extract_dir)
                safe_extract(jar_path, extract_dir)
                log.debug(f"Extracted JAR {jar_file} to {extract_dir}")
            
            # Look for pom.xml in extracted content or in the original directory
            extracted_pom = os.path.join(extract_dir, "META-INF", "maven")
            package_info = {}
            
            # Try to find POM in META-INF/maven structure
            if os.path.exists(extracted_pom):
                for root, dirs, files in os.walk(extracted_pom):
                    for file in files:
                        if file == "pom.xml":
                            pom_file_path = os.path.join(root, file)
                            package_info = self._parse_pom(pom_file_path)
                            break
                    if package_info:
                        break
            
            # Fallback: check if there's a pom.xml in the original directory
            if not package_info and os.path.exists(pom_path):
                package_info = self._parse_pom(pom_path)
            
            # If still no package info, create minimal info from JAR filename
            if not package_info:
                jar_name = os.path.splitext(jar_file)[0]
                package_info = {
                    "info": {
                        "name": jar_name,
                        "version": "unknown"
                    }
                }
                log.warning(f"Could not find POM information for {jar_file}, using filename as package name")
            
            return package_info, extract_dir
        
        # Fallback: try just pom.xml without Java files (project directory)
        if os.path.exists(pom_path):
            log.debug(f"Found pom.xml in {path} but no Java source files")
            package_info = self._parse_pom(pom_path)
            return package_info, path
            
        raise Exception(f"No pom.xml or JAR files found in {path}") 