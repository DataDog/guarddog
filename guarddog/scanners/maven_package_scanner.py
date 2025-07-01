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

    def download_package(self, package_name: str, directory: str, version: typing.Optional[str] = None) -> str:
        if version is None:
            raise ValueError("Version must be specified for Maven packages")

        local_maven_repo = os.path.expanduser("~/.m2/repository")

        sources_path_in_repo = self._get_path_for_artifact(package_name, version, classifier="sources", extension="jar")
        full_sources_path = os.path.join(local_maven_repo, sources_path_in_repo)

        if not os.path.exists(full_sources_path):
            raise FileNotFoundError(f"Could not find {package_name}:{version} sources in local Maven repository. "
                                  f"Looked for {full_sources_path}")

        _, artifact_id = package_name.split(":")
        destination_jar = os.path.join(directory, f"{artifact_id}-{version}-sources.jar")
        shutil.copyfile(full_sources_path, destination_jar)

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
        pom_path = os.path.join(path, "pom.xml")
        if not os.path.exists(pom_path):
            raise Exception(f"pom.xml not found in {path}")

        package_info = self._parse_pom(pom_path)
        return package_info, path 