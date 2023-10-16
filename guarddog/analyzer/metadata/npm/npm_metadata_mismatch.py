from typing import Optional, Any, Union, get_args
from pathlib import Path
import json

from guarddog.analyzer.metadata.detector import Detector

# List of fields where mismatch between package.json and NPM can carry malicious information
# (field, expected type)
MANIFEST_FIELDS_CHECKLIST = {
    "dependencies": dict, 
    "devDependencies": dict, 
    "scripts": dict,
    "main": str, 
    "repository": dict, 
    "bugs": dict, 
    "homepage": str
}

class NPMMetadataMismatch(Detector):
    def __init__(self):
        super().__init__(
            name="npm_metadata_mismatch",
            description="Identify packages which have mismatches between the npm pacakge manifest and the package info"
        )

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, Optional[str]]:
        # Get the latest version if not specified
        if not version:
            version = package_info["dist-tags"]["latest"]

        # Load package.json manifest
        if path is None:
            raise ValueError("path is needed to run heuristic " + self.get_name())
        package_json = Path(path) / "package" / "package.json"
        package_manifest: dict[Any] = json.loads(package_json.read_text())

        # Get NPM manifest for version
        version_info = package_info["versions"][version] 

        diff: dict[str, Diff] = {
            field: difference_at_key(version_info, package_manifest, field, field_type)
            for field, field_type in MANIFEST_FIELDS_CHECKLIST.items()
        }
        number_different = sum(len(v) for k,v in diff.items())
        diff_description = describe_diff(diff) if number_different != 0 else "No differences found"
        return number_different != 0, diff_description

PerItemDiff = tuple[str,str,str]
Diff = list[PerItemDiff] 

def diff_at_key_dict(version_at_key: dict[str,Any], manifest_at_key: dict[str,Any]) -> Diff:
    return [
        (key, version_at_key.get(key), manifest_at_key.get(key))
        for key in set(version_at_key.keys()).union(set(manifest_at_key.keys())) 
        if version_at_key.get(key) != manifest_at_key.get(key)
    ]

def difference_at_key(version_info: dict[str,Any], package_manifest: dict[str,Any], key: str, key_type) -> Diff:
    version_at_key = version_info.get(key, key_type())
    manifest_at_key = package_manifest.get(key, key_type())
    if not(isinstance(version_at_key, key_type) and isinstance(manifest_at_key, key_type)):
        return [(f"Expected type {str(key_type)}", f"{type(version_at_key)}", f"{type(manifest_at_key)}")]
    elif key_type == dict:
        return diff_at_key_dict(version_at_key, manifest_at_key)
    else:
        # If it is not a dict do a direct comparison of the value at the key, currently the only other type is strings
        return [(f"{key}", version_at_key, manifest_at_key)] if version_at_key != manifest_at_key else []


def describe_diff(diff: dict[str,Diff]) -> str:
    """
    Creates a string of the form 
    Difference between manifest and package.json found:
    dependencies:
        key: Manifest("v4.0.0"), package.json("v3.0.1")
    scripts:
        key: Manifest("a"), package.json("b")
    main:
        Manifest:
            index.js
        package.json
            malicious.js
    ...
    """
    description = "Difference between manifest and package.json found: \n"
    for k, differences in diff.items():
        if differences:
            field_description = f"{k}: \n"
            if MANIFEST_FIELDS_CHECKLIST[k] == dict:
                for d in differences:
                    field_description += f"  {d[0]}: Manifest(\"{d[1]}\"), package.json(\"{d[2]}\") \n"
            else:
                manifest_str = "  Manifest:\n"
                package_str = "  package.json:\n"
                for d in differences:
                    manifest_str += f"    {d[1]}\n"
                    package_str += f"    {d[2]}\n"
                field_description = field_description + manifest_str + package_str
            description += field_description
    return description
