import logging
import os
from typing import List
import xml.etree.ElementTree as ET

from guarddog.scanners.maven_package_scanner import MavenPackageScanner
from guarddog.scanners.scanner import Dependency, ProjectScanner

log = logging.getLogger("guarddog")


class MavenProjectScanner(ProjectScanner):
    def __init__(self) -> None:
        super().__init__(MavenPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            root = ET.fromstring(raw_requirements)
            namespace = ""
            if '}' in root.tag:
                namespace = root.tag.split('}')[0].strip('{')

            def find_text(elem, tag):
                ns_tag = f"{{{namespace}}}{tag}" if namespace else tag
                found = elem.find(ns_tag)
                return found.text if found is not None else None

            properties = {}
            props_element = root.find(f"{{{namespace}}}properties" if namespace else "properties")
            if props_element is not None:
                for prop in props_element:
                    tag = prop.tag.replace(f"{{{namespace}}}", "")
                    properties[tag.strip()] = prop.text.strip() if prop.text else ""

            deps_element = root.find(f"{{{namespace}}}dependencies" if namespace else "dependencies")
            if deps_element is None:
                return []

            for dep_element in deps_element.findall(f"{{{namespace}}}dependency" if namespace else "dependency"):
                group_id = find_text(dep_element, "groupId")
                artifact_id = find_text(dep_element, "artifactId")
                version_text = find_text(dep_element, "version")

                if not group_id or not artifact_id or not version_text:
                    continue

                if version_text.startswith("${") and version_text.endswith("}"):
                    prop_name = version_text[2:-1]
                    if prop_name in properties:
                        version_text = properties[prop_name]
                    else:
                        log.warning(f"Could not resolve version property {version_text} in pom.xml")
                        continue

                dep_name = f"{group_id}:{artifact_id}"
                idx = 0
                for i, line in enumerate(raw_requirements.splitlines()):
                    if artifact_id in line:
                        idx = i + 1
                        break
                
                from guarddog.scanners.scanner import DependencyVersion
                dep_version = DependencyVersion(version=version_text, location=idx)

                dep = next(
                    filter(
                        lambda d: d.name == dep_name,
                        dependencies,
                    ),
                    None,
                )
                if not dep:
                    dep = Dependency(name=dep_name, versions=set())
                    dependencies.append(dep)

                dep.versions.add(dep_version)

        except ET.ParseError as e:
            log.warning(f"Could not parse pom.xml: {e}")

        return dependencies

    def find_requirements(self, directory: str) -> list[str]:
        # The relevant file is pom.xml
        requirement_files = []
        for root, dirs, files in os.walk(directory):
            for name in files:
                if name == 'pom.xml':
                    requirement_files.append(os.path.join(root, name))
        return requirement_files 