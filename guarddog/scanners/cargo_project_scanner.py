import json
import os
from typing import List

from guarddog.scanners.crates_package_scanner import CratesPackageScanner
from guarddog.scanners.scanner import Dependency, DependencyVersion, ProjectScanner

CRATES_IO_INDEX = "registry+https://github.com/rust-lang/crates.io-index"


class CargoLockScanner(ProjectScanner):
    def __init__(self) -> None:
        super().__init__(CratesPackageScanner())

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        packages: list[dict[str, tuple[str, int]]] = []
        current_package: dict[str, tuple[str, int]] | None = None

        for line_number, line in enumerate(raw_requirements.splitlines(), start=1):
            stripped = line.strip()
            if stripped == "[[package]]":
                if current_package is not None:
                    packages.append(current_package)
                current_package = {}
                continue

            if current_package is None or "=" not in stripped:
                continue

            key, raw_value = (part.strip() for part in stripped.split("=", maxsplit=1))
            if key not in {"name", "version", "source"}:
                continue
            try:
                value = json.loads(raw_value)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(value, str):
                current_package[key] = (value, line_number)

        if current_package is not None:
            packages.append(current_package)

        dependencies: list[Dependency] = []
        for package in packages:
            if package.get("source", ("", 0))[0] != CRATES_IO_INDEX:
                continue
            if "name" not in package or "version" not in package:
                continue

            name, location = package["name"]
            version = package["version"][0]
            dependency = next(
                (dependency for dependency in dependencies if dependency.name == name),
                None,
            )
            if dependency is None:
                dependency = Dependency(name=name, versions=set())
                dependencies.append(dependency)
            dependency.versions.add(
                DependencyVersion(version=version, location=location)
            )

        return dependencies

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []
        for root, _, files in os.walk(directory):
            for name in files:
                if name == "Cargo.lock":
                    requirement_files.append(os.path.join(root, name))
        return requirement_files
