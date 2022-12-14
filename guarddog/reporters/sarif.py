import json

def _get_npm_region(package_path: str, package: str) -> dict:
    pass


def report_npm_verify_sarif(package_path: str, rules: list[str], scan_results: list[dict]) -> str:
    results = []
    for entry in scan_results:
        if entry["results"]["issues"] == 0:
            continue
        location = _get_npm_region(package_path, entry["dependency"])
        fingerprint = json.dumps(entry)  # TODO: hash



