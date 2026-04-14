#!/usr/bin/env python3
"""
Build a cluster index for the malicious-software-packages dataset.

Downloads package ZIPs from GitHub, fingerprints each one inside a Nono
sandbox, and groups packages by code similarity. The resulting
cluster_index.json is used by recall.py for diverse sampling.

For malicious_intent packages: hashes the full normalized source code.
For compromised_lib packages: runs guarddog, then hashes threat code snippets.

Usage:
    uv run evals/cluster.py
    uv run evals/cluster.py --ecosystems pypi --workers 10
    uv run evals/cluster.py --dataset-path /path/to/local/clone
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from evals import templates


EVALS_DIR = Path(__file__).parent
DEFAULT_WORK_DIR = EVALS_DIR / "workdir"
CLUSTER_INDEX_FILE = EVALS_DIR / "cluster_index.json"
WORKER_SCRIPT = EVALS_DIR / "cluster_worker.py"

DATASET_REPO = "DataDog/malicious-software-packages-dataset"
MAX_ZIP_SIZE_BYTES_DEFAULT = 100 * 1024 * 1024  # 100 MB

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".rb", ".go"}


def parse_args():
    p = argparse.ArgumentParser(description="Build cluster index for malicious packages dataset")
    p.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    p.add_argument("--ecosystems", nargs="+", choices=["pypi", "npm"], default=["pypi", "npm"])
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--timeout", type=int, default=120,
                   help="Per-package fingerprinting timeout in seconds")
    p.add_argument("--max-zip-size", type=int, default=100,
                   help="Skip ZIPs larger than this (MB). Skipped packages become singletons.")
    p.add_argument("--dataset-path", type=Path, default=None,
                   help="Path to local clone of malicious-software-packages-dataset")
    p.add_argument("--tlsh-threshold", type=int, default=100,
                   help="TLSH distance threshold for fuzzy clustering (0=exact only)")
    p.add_argument("--no-sandbox", action="store_true",
                   help="Skip Nono sandbox (DANGEROUS, for testing only)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# GitHub API helpers (same pattern as recall.py)
# ---------------------------------------------------------------------------

def _github_headers() -> dict:
    headers = {"User-Agent": "guarddog-evals/1.0", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _github_api(endpoint: str) -> dict | list:
    return _fetch_json(f"https://api.github.com/{endpoint}")


# ---------------------------------------------------------------------------
# Phase 1: Enumerate all packages from manifests
# ---------------------------------------------------------------------------

def enumerate_packages(ecosystems: list[str], dataset_path: Path | None) -> tuple[str, list[dict]]:
    """Return (dataset_sha, list of package dicts with ecosystem/category/package fields)."""
    sha = _github_api(f"repos/{DATASET_REPO}/commits/main")["sha"]
    print(f"Dataset SHA: {sha}")

    packages = []
    for eco in ecosystems:
        if dataset_path:
            manifest_path = dataset_path / "samples" / eco / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
        else:
            url = f"https://raw.githubusercontent.com/{DATASET_REPO}/main/samples/{eco}/manifest.json"
            manifest = _fetch_json(url)

        for pkg_name, meta in manifest.items():
            category = "compromised_lib" if meta is not None else "malicious_intent"
            packages.append({"package": pkg_name, "ecosystem": eco, "category": category})

        compromised = sum(1 for v in manifest.values() if v is not None)
        malicious = sum(1 for v in manifest.values() if v is None)
        print(f"  {eco}: {malicious} malicious_intent + {compromised} compromised_lib = {len(manifest)} total")

    return sha, packages


# ---------------------------------------------------------------------------
# Phase 2: Resolve ZIP paths
# ---------------------------------------------------------------------------

def _get_subtree_sha(parent_sha: str, child_name: str) -> str | None:
    """Get the tree SHA for a child directory within a parent tree."""
    tree_data = _github_api(f"repos/{DATASET_REPO}/git/trees/{parent_sha}")
    for entry in tree_data.get("tree", []):
        if entry.get("path") == child_name and entry.get("type") == "tree":
            return entry["sha"]
    return None


def _build_zip_index_from_tree(sha: str, ecosystems: list[str]) -> dict[str, str]:
    """Fetch ZIP paths by walking the repo tree per ecosystem/category.

    Returns a dict mapping "ecosystem/category/package" -> "samples/.../file.zip"
    (the latest version's ZIP for each package).

    Walks the tree hierarchy: root -> samples -> {eco} -> {cat} -> recursive.
    Uses ~10 API calls total instead of 2 per package (~23k).
    """
    print("  Walking repository tree to find all ZIPs...")

    # Navigate: root -> samples
    samples_sha = _get_subtree_sha(sha, "samples")
    if not samples_sha:
        print("  ERROR: 'samples' directory not found in repo tree")
        return {}

    pkg_zips = defaultdict(list)
    categories = ["malicious_intent", "compromised_lib"]

    for eco in ecosystems:
        eco_sha = _get_subtree_sha(samples_sha, eco)
        if not eco_sha:
            print(f"  WARNING: samples/{eco} not found")
            continue

        for cat in categories:
            cat_sha = _get_subtree_sha(eco_sha, cat)
            if not cat_sha:
                continue

            # Recursive tree for this category (typically < 10k entries, no truncation)
            tree_data = _github_api(f"repos/{DATASET_REPO}/git/trees/{cat_sha}?recursive=1")
            if tree_data.get("truncated"):
                print(f"  WARNING: tree for {eco}/{cat} was truncated")

            for entry in tree_data.get("tree", []):
                path = entry.get("path", "")
                if not path.endswith(".zip"):
                    continue
                # Expected: {pkg}/{version}/{file}.zip (3 parts)
                # Scoped npm packages use @ as separator: @scope@name/{version}/{file}.zip
                parts = path.split("/")
                if len(parts) != 3:
                    continue
                pkg, version, _filename = parts
                # Convert @scope@name back to @scope/name (manifest format)
                if pkg.startswith("@") and "@" in pkg[1:]:
                    idx = pkg.index("@", 1)
                    pkg = pkg[:idx] + "/" + pkg[idx + 1:]
                key = f"{eco}/{cat}/{pkg}"
                full_path = f"samples/{eco}/{cat}/{path}"
                pkg_zips[key].append((version, full_path))

            cat_count = len([k for k in pkg_zips if k.startswith(f"{eco}/{cat}/")])
            print(f"  {eco}/{cat}: {cat_count} packages")

    # For each package, pick the latest version
    index = {}
    for key, versions in pkg_zips.items():
        versions.sort(key=lambda x: x[0])
        _version, zip_path = versions[-1]
        index[key] = zip_path

    print(f"  Total: {len(index)} package ZIPs found")
    return index


def _resolve_zip_path_api(pkg: dict, sha: str) -> str | None:
    """Fallback: resolve a single package's ZIP path via per-package API calls."""
    import urllib.parse
    dir_path = f"samples/{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
    encoded_path = urllib.parse.quote(dir_path, safe="/")
    try:
        entries = _github_api(f"repos/{DATASET_REPO}/contents/{encoded_path}?ref={sha}")
        versions = sorted([e["name"] for e in entries if e["type"] == "dir"])
        if not versions:
            return None
        version_path = urllib.parse.quote(f"{dir_path}/{versions[-1]}", safe="/")
        files = _github_api(f"repos/{DATASET_REPO}/contents/{version_path}?ref={sha}")
        zips = [f for f in files if f["name"].endswith(".zip")]
        return zips[0]["path"] if zips else None
    except Exception:
        return None


def _resolve_zip_path_local(pkg: dict, dataset_path: Path) -> str | None:
    """Find the latest ZIP path for a package from a local clone."""
    dir_path = f"samples/{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
    local_dir = dataset_path / dir_path
    if not local_dir.is_dir():
        return None
    versions = sorted([d.name for d in local_dir.iterdir() if d.is_dir()])
    if not versions:
        return None
    version_dir = local_dir / versions[-1]
    zips = sorted([f.name for f in version_dir.iterdir() if f.suffix == ".zip"])
    if not zips:
        return None
    return str(version_dir / zips[0])


def resolve_all_zip_paths(packages: list[dict], dataset_path: Path | None,
                          dataset_sha: str, ecosystems: list[str],
                          workers: int) -> list[dict]:
    """Resolve ZIP paths for all packages. Returns packages with zip_path set."""
    print(f"Resolving ZIP paths for {len(packages)} packages...")

    if dataset_path:
        # Local clone: resolve in parallel via filesystem
        resolved = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 20)) as executor:
            future_to_idx = {
                executor.submit(_resolve_zip_path_local, pkg, dataset_path): i
                for i, pkg in enumerate(packages)
            }
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    packages[idx]["zip_path"] = future.result()
                except Exception:
                    packages[idx]["zip_path"] = None
                if packages[idx]["zip_path"]:
                    resolved += 1
    else:
        # GitHub: walk the tree per ecosystem/category (~10 API calls total)
        zip_index = _build_zip_index_from_tree(dataset_sha, ecosystems)
        resolved = 0
        missing = []
        for i, pkg in enumerate(packages):
            key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
            pkg["zip_path"] = zip_index.get(key)
            if pkg["zip_path"]:
                resolved += 1
            else:
                missing.append(i)

        # Fallback: resolve missing packages via per-package API calls
        if missing:
            print(f"  {len(missing)} packages not in tree, resolving via API fallback...")
            import urllib.parse
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 20)) as executor:
                future_to_idx = {
                    executor.submit(_resolve_zip_path_api, pkg, dataset_sha): i
                    for i, pkg in ((idx, packages[idx]) for idx in missing)
                }
                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        packages[idx]["zip_path"] = future.result()
                    except Exception:
                        packages[idx]["zip_path"] = None
                    if packages[idx]["zip_path"]:
                        resolved += 1

    before = len(packages)
    packages = [p for p in packages if p.get("zip_path")]
    print(f"  {resolved} resolved, {before - resolved} failed")
    return packages


# ---------------------------------------------------------------------------
# Phase 3: Download ZIPs
# ---------------------------------------------------------------------------

def _download_zip(pkg: dict, zip_dir: Path, sha: str, dataset_path: Path | None,
                  max_size_bytes: int) -> tuple[Path | None, str | None]:
    """Download a single ZIP. Returns (local_path, error)."""
    safe_name = pkg["package"].replace("@", "_at_").replace("/", "__")
    local_zip = zip_dir / pkg["ecosystem"] / pkg["category"] / f"{safe_name}.zip"

    if local_zip.exists():
        if local_zip.stat().st_size > max_size_bytes:
            return None, f"cached but too large ({local_zip.stat().st_size} bytes)"
        return local_zip, None

    if dataset_path:
        src = Path(pkg["zip_path"])
        if not src.exists():
            return None, "local ZIP not found"
        if src.stat().st_size > max_size_bytes:
            return None, f"too large ({src.stat().st_size} bytes)"
        local_zip.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, local_zip)
        return local_zip, None

    url = f"https://raw.githubusercontent.com/{DATASET_REPO}/{sha}/{pkg['zip_path']}"
    try:
        local_zip.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "guarddog-evals/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > max_size_bytes:
                return None, f"too large ({content_length} bytes)"
            data = resp.read()
            if len(data) > max_size_bytes:
                return None, f"too large ({len(data)} bytes)"
            local_zip.write_bytes(data)
        return local_zip, None
    except Exception as e:
        return None, str(e)[:200]


def download_all_zips(packages: list[dict], zip_dir: Path, sha: str,
                      dataset_path: Path | None, max_size_mb: int, workers: int) -> dict[str, Path]:
    """Download ZIPs for all packages. Returns {package_key: local_path}."""
    zip_dir.mkdir(parents=True, exist_ok=True)
    max_size_bytes = max_size_mb * 1024 * 1024

    print(f"Downloading {len(packages)} ZIPs (max {max_size_mb} MB, {workers} workers)...")
    downloaded = 0
    cached = 0
    skipped = 0
    errors = 0
    pkg_to_zip = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 20)) as executor:
        future_to_pkg = {
            executor.submit(_download_zip, pkg, zip_dir, sha, dataset_path, max_size_bytes): pkg
            for pkg in packages
        }
        done = 0
        for future in concurrent.futures.as_completed(future_to_pkg):
            pkg = future_to_pkg[future]
            key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
            done += 1
            try:
                local_path, error = future.result()
                if local_path:
                    pkg_to_zip[key] = local_path
                    if "cached" not in str(error or ""):
                        downloaded += 1
                    else:
                        cached += 1
                elif error and "too large" in error:
                    skipped += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

            if done % 500 == 0 or done == len(packages):
                print(f"  [{done}/{len(packages)}] {downloaded} new, {cached} cached, "
                      f"{skipped} skipped (too large), {errors} errors")

    print(f"  Total: {len(pkg_to_zip)} ZIPs ready")
    return pkg_to_zip


# ---------------------------------------------------------------------------
# Phase 3b: Detect empty ZIPs (no source files)
# ---------------------------------------------------------------------------

ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar.gz", ".tgz", ".tar.bz2", ".whl", ".gem"})


def _zip_has_source_files(zip_path: Path) -> bool:
    """Return True if the ZIP contains at least one source file or nested archive.

    Source files are identified by extension. Directories and metadata files
    matching package_info-*.json are ignored. Nested archives (.zip, .whl, etc.)
    count as "has content" since they likely contain the actual package.
    """
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                basename = os.path.basename(info.filename)
                if basename.startswith("package_info-") and basename.endswith(".json"):
                    continue
                ext = os.path.splitext(basename)[1].lower()
                if ext in SOURCE_EXTENSIONS:
                    return True
                # Nested archives (e.g. double-wrapped ZIPs) contain the real package
                if ext in ARCHIVE_EXTENSIONS or info.filename.endswith(".tar.gz"):
                    return True
    except Exception:
        pass
    return False


def find_empty_packages(pkg_to_zip: dict[str, Path], workers: int) -> list[str]:
    """Return package keys whose ZIPs contain no source files."""
    print(f"Checking {len(pkg_to_zip)} ZIPs for source files...")
    empty = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 20)) as executor:
        future_to_key = {
            executor.submit(_zip_has_source_files, zip_path): key
            for key, zip_path in pkg_to_zip.items()
        }
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                has_source = future.result()
            except Exception:
                has_source = False
            if not has_source:
                empty.append(key)

    empty.sort()
    print(f"  {len(empty)} empty packages (no source files)")
    return empty


# ---------------------------------------------------------------------------
# Phase 4: Fingerprint (sandboxed workers)
# ---------------------------------------------------------------------------

def find_guarddog_bin() -> str:
    venv_bin = EVALS_DIR.parent / ".venv" / "bin" / "guarddog"
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which("guarddog")
    if found:
        return found
    sys.exit("ERROR: guarddog not found. Run 'uv pip install -e .' from the repo root first.")


def _fingerprint_one(pkg: dict, zip_path: Path, guarddog_bin: str,
                     timeout: int, no_sandbox: bool) -> dict:
    """Run cluster_worker.py on a single package. Returns {key, fingerprint, error, ...}."""
    key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
    tmp_base = os.path.realpath(tempfile.gettempdir())
    output_fd, output_path = tempfile.mkstemp(dir=tmp_base, suffix=".json", prefix="gd_cluster_")
    os.close(output_fd)

    cmd = [
        sys.executable, str(WORKER_SCRIPT),
        "--zip-path", str(zip_path.resolve()),
        "--ecosystem", pkg["ecosystem"],
        "--category", pkg["category"],
        "--package-name", pkg["package"],
        "--output-path", output_path,
        "--guarddog-bin", guarddog_bin,
    ]
    if no_sandbox:
        cmd.append("--no-sandbox")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       cwd=str(EVALS_DIR.parent))

        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path) as f:
                result = json.load(f)
            return {"key": key, **result}
        return {"key": key, "fingerprint": "", "file_count": 0, "total_bytes": 0,
                "error": "worker produced no output"}

    except subprocess.TimeoutExpired:
        return {"key": key, "fingerprint": "", "file_count": 0, "total_bytes": 0,
                "error": f"timeout after {timeout}s"}
    except Exception as e:
        return {"key": key, "fingerprint": "", "file_count": 0, "total_bytes": 0,
                "error": str(e)[:300]}
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def fingerprint_all(packages: list[dict], pkg_to_zip: dict[str, Path],
                    guarddog_bin: str, workers: int, timeout: int,
                    no_sandbox: bool) -> dict[str, dict]:
    """Fingerprint all packages in parallel. Returns {key: {fingerprint, file_count, ...}}."""
    to_process = []
    for pkg in packages:
        key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
        if key in pkg_to_zip:
            to_process.append((pkg, pkg_to_zip[key]))

    print(f"Fingerprinting {len(to_process)} packages ({workers} workers, {timeout}s timeout)...")
    results = {}
    errors = 0
    error_types = defaultdict(int)
    error_examples = {}
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_key = {}
        for pkg, zip_path in to_process:
            key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
            fut = executor.submit(_fingerprint_one, pkg, zip_path, guarddog_bin, timeout, no_sandbox)
            future_to_key[fut] = key

        done = 0
        for fut in concurrent.futures.as_completed(future_to_key):
            done += 1
            try:
                result = fut.result()
                results[result["key"]] = result
                if result.get("error"):
                    errors += 1
                    err_msg = result["error"]
                    # Bucket errors by first line / first 60 chars
                    err_type = err_msg.split("\n")[0][:60]
                    error_types[err_type] += 1
                    if err_type not in error_examples:
                        error_examples[err_type] = result["key"]
            except Exception as e:
                errors += 1

            if done % 200 == 0 or done == len(to_process):
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (len(to_process) - done) / rate if rate > 0 else 0
                print(f"  [{done}/{len(to_process)}] {errors} errors | {elapsed:.0f}s | ETA {eta:.0f}s")

    print(f"  Done: {len(results)} fingerprinted, {errors} errors, {time.time() - start:.0f}s total")
    if error_types:
        print(f"  Error breakdown:")
        for err_type, count in sorted(error_types.items(), key=lambda x: -x[1]):
            example = error_examples[err_type]
            print(f"    {count:5d}x  {err_type}")
            print(f"           e.g. {example}")
    return results


# ---------------------------------------------------------------------------
# Phase 5: Build cluster index
# ---------------------------------------------------------------------------

def _merge_clusters_tlsh(sha_clusters: dict[str, list[str]],
                         tlsh_hashes: dict[str, str],
                         threshold: int) -> dict[str, list[str]]:
    """Merge SHA-256 clusters that are similar by TLSH distance.

    For each cluster, pick a representative TLSH hash (first member that has one).
    Then use union-find to merge clusters whose representatives are within threshold.
    """
    import tlsh

    # Build representative TLSH hash per SHA cluster
    cluster_ids = list(sha_clusters.keys())
    cluster_tlsh = {}
    for cid in cluster_ids:
        for member in sha_clusters[cid]:
            h = tlsh_hashes.get(member, "")
            if h:
                cluster_tlsh[cid] = h
                break

    # Union-Find
    parent = {cid: cid for cid in cluster_ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[a] = b

    # Compare all cluster pairs that have TLSH hashes
    tlsh_cids = [cid for cid in cluster_ids if cid in cluster_tlsh]
    comparisons = 0
    merges = 0
    for i in range(len(tlsh_cids)):
        for j in range(i + 1, len(tlsh_cids)):
            if find(tlsh_cids[i]) == find(tlsh_cids[j]):
                continue
            comparisons += 1
            dist = tlsh.diff(cluster_tlsh[tlsh_cids[i]], cluster_tlsh[tlsh_cids[j]])
            if dist <= threshold:
                union(tlsh_cids[i], tlsh_cids[j])
                merges += 1

    print(f"  TLSH merging: {comparisons} comparisons, {merges} merges (threshold={threshold})")

    # Rebuild clusters from union-find
    merged = defaultdict(list)
    for cid in cluster_ids:
        root = find(cid)
        merged[root].extend(sha_clusters[cid])

    return dict(merged)


def build_cluster_index(dataset_sha: str, packages: list[dict], fingerprint_results: dict[str, dict],
                        max_zip_size_mb: int, tlsh_threshold: int,
                        empty_packages: list[str] | None = None) -> dict:
    """Group packages by fingerprint, then merge similar clusters via TLSH."""
    fingerprints = {}
    tlsh_hashes = {}
    sha_clusters = defaultdict(list)
    skipped = 0
    errored = 0

    for pkg in packages:
        key = f"{pkg['ecosystem']}/{pkg['category']}/{pkg['package']}"
        result = fingerprint_results.get(key)

        if not result:
            skipped += 1
            continue

        fp = result.get("fingerprint", "")
        if not fp:
            errored += 1
            continue

        fingerprints[key] = fp
        sha_clusters[fp].append(key)

        tlsh_h = result.get("tlsh", "")
        if tlsh_h:
            tlsh_hashes[key] = tlsh_h

    exact_count = len(sha_clusters)
    print(f"  SHA-256 exact clusters: {exact_count}")

    # Phase 2: merge similar clusters via TLSH
    if tlsh_threshold > 0 and tlsh_hashes:
        clusters = _merge_clusters_tlsh(sha_clusters, tlsh_hashes, tlsh_threshold)
    else:
        clusters = dict(sha_clusters)

    # Assign stable cluster IDs (SHA-256 of sorted member list)
    import hashlib
    stable_clusters = {}
    key_to_cluster = {}
    for members in clusters.values():
        members.sort()
        cluster_id = hashlib.sha256(",".join(members).encode()).hexdigest()[:16]
        stable_clusters[cluster_id] = members
        for m in members:
            key_to_cluster[m] = cluster_id

    cluster_sizes = sorted([len(v) for v in stable_clusters.values()], reverse=True)
    singletons = sum(1 for s in cluster_sizes if s == 1)

    index = {
        "dataset_sha": dataset_sha,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": {"max_zip_size_mb": max_zip_size_mb, "tlsh_threshold": tlsh_threshold},
        "fingerprints": key_to_cluster,
        "tlsh_hashes": tlsh_hashes,
        "sha_clusters": {k: v for k, v in sha_clusters.items()},
        "clusters": stable_clusters,
        "empty_packages": empty_packages or [],
        "stats": {
            "total_packages": len(packages),
            "fingerprinted": len(fingerprints),
            "skipped": skipped,
            "errored": errored,
            "exact_clusters": exact_count,
            "total_clusters": len(stable_clusters),
            "largest_cluster": cluster_sizes[0] if cluster_sizes else 0,
            "singletons": singletons,
            "empty": len(empty_packages) if empty_packages else 0,
        },
    }

    return index


def print_summary(index: dict):
    stats = index["stats"]
    print(f"\n{'='*60}")
    print(f"  Cluster Index Summary")
    print(f"  Dataset SHA: {index['dataset_sha'][:12]}...")
    print(f"  Total packages: {stats['total_packages']}")
    print(f"  Fingerprinted: {stats['fingerprinted']}")
    print(f"  Skipped (too large / not downloaded): {stats['skipped']}")
    print(f"  Errored: {stats['errored']}")
    if "exact_clusters" in stats:
        print(f"  Exact (SHA-256) clusters: {stats['exact_clusters']}")
        print(f"  After TLSH merging: {stats['total_clusters']}")
    else:
        print(f"  Total clusters: {stats['total_clusters']}")
    print(f"  Largest cluster: {stats['largest_cluster']}")
    print(f"  Singletons: {stats['singletons']}")
    if stats.get("empty"):
        print(f"  Empty packages (no source files): {stats['empty']}")

    # Top 10 largest clusters
    clusters = index["clusters"]
    top = sorted(clusters.items(), key=lambda x: -len(x[1]))[:10]
    if top:
        print(f"\n  Top 10 clusters:")
        for fp, members in top:
            sample = members[0].split("/")[-1]
            print(f"    {len(members):4d} packages  (e.g. {sample})  fp={fp[:12]}...")

    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Phase 6: HTML report
# ---------------------------------------------------------------------------

def _compute_clusters_at_threshold(sha_clusters: dict[str, list[str]],
                                    tlsh_hashes: dict[str, str],
                                    threshold: int) -> dict:
    """Compute clustering stats at a given TLSH threshold. Returns summary dict."""
    import tlsh

    cluster_ids = list(sha_clusters.keys())
    if threshold == 0 or not tlsh_hashes:
        merged = sha_clusters
    else:
        cluster_tlsh = {}
        for cid in cluster_ids:
            for member in sha_clusters[cid]:
                h = tlsh_hashes.get(member, "")
                if h:
                    cluster_tlsh[cid] = h
                    break

        parent = {cid: cid for cid in cluster_ids}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        def union(a, b):
            a, b = find(a), find(b)
            if a != b:
                parent[a] = b

        tlsh_cids = [cid for cid in cluster_ids if cid in cluster_tlsh]
        for i in range(len(tlsh_cids)):
            for j in range(i + 1, len(tlsh_cids)):
                if find(tlsh_cids[i]) == find(tlsh_cids[j]):
                    continue
                dist = tlsh.diff(cluster_tlsh[tlsh_cids[i]], cluster_tlsh[tlsh_cids[j]])
                if dist <= threshold:
                    union(tlsh_cids[i], tlsh_cids[j])

        merged = defaultdict(list)
        for cid in cluster_ids:
            merged[find(cid)].extend(sha_clusters[cid])
        merged = dict(merged)

    sizes = sorted([len(m) for m in merged.values()], reverse=True)
    size_counts = Counter(sizes)
    singletons = sum(1 for s in sizes if s == 1)
    total_pkgs = sum(sizes)

    bucket_ranges = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 10), (11, 20), (21, 50), (51, 100), (101, 999999)]
    buckets = [sum(cnt for sz, cnt in size_counts.items() if lo <= sz <= hi)
               for lo, hi in bucket_ranges]

    # Top 10 clusters
    top = sorted(merged.values(), key=len, reverse=True)[:10]
    top_info = []
    for members in top:
        names = [m.split("/")[-1] for m in members[:5]]
        extra = len(members) - 5
        label = ", ".join(names)
        if extra > 0:
            label += f", ... (+{extra})"
        top_info.append({"size": len(members), "examples": label})

    return {
        "threshold": threshold,
        "total_clusters": len(merged),
        "singletons": singletons,
        "largest": sizes[0] if sizes else 0,
        "dedup_ratio": round(total_pkgs / max(len(merged), 1), 1),
        "buckets": buckets,
        "top_clusters": top_info,
    }


def build_cluster_report(index: dict, work_dir: Path):
    """Generate an HTML report with clustering statistics and a threshold slider."""
    stats = index["stats"]
    config = index.get("config", {})
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    current_threshold = config.get("tlsh_threshold", 100)

    # Precompute stats at multiple thresholds
    sha_clusters = index.get("sha_clusters", {})
    tlsh_hashes = index.get("tlsh_hashes", {})

    thresholds = [0, 20, 40, 60, 80, 100, 120, 150, 200]
    if current_threshold not in thresholds:
        thresholds.append(current_threshold)
        thresholds.sort()

    print("  Precomputing clustering at multiple thresholds...")
    threshold_data = []
    for t in thresholds:
        td = _compute_clusters_at_threshold(sha_clusters, tlsh_hashes, t)
        threshold_data.append(td)

    threshold_data_json = json.dumps(threshold_data)

    # Per-ecosystem and per-category breakdowns (static, from the active clusters)
    clusters = index["clusters"]

    eco_stats = defaultdict(lambda: {"packages": 0, "clusters": set()})
    for cid, members in clusters.items():
        for m in members:
            eco = m.split("/")[0]
            eco_stats[eco]["packages"] += 1
            eco_stats[eco]["clusters"].add(cid)

    eco_rows = ""
    for eco in sorted(eco_stats.keys()):
        s = eco_stats[eco]
        n_clusters = len(s["clusters"])
        n_pkgs = s["packages"]
        ratio = n_pkgs / n_clusters if n_clusters else 0
        eco_rows += (f"<tr><td>{escape(eco.upper())}</td><td>{n_pkgs}</td>"
                     f"<td>{n_clusters}</td><td>{ratio:.1f}</td></tr>\n")

    cat_stats = defaultdict(lambda: {"packages": 0, "clusters": set()})
    for cid, members in clusters.items():
        for m in members:
            cat = m.split("/")[1]
            cat_stats[cat]["packages"] += 1
            cat_stats[cat]["clusters"].add(cid)

    cat_rows = ""
    for cat in sorted(cat_stats.keys()):
        s = cat_stats[cat]
        n_clusters = len(s["clusters"])
        n_pkgs = s["packages"]
        ratio = n_pkgs / n_clusters if n_clusters else 0
        cat_rows += (f"<tr><td>{escape(cat)}</td><td>{n_pkgs}</td>"
                     f"<td>{n_clusters}</td><td>{ratio:.1f}</td></tr>\n")

    bucket_labels_json = json.dumps(["1", "2", "3", "4", "5", "6-10", "11-20", "21-50", "51-100", "100+"])

    body = f"""
<h1>Cluster Index Report</h1>
<p class="meta">Generated {ts} &mdash; Dataset SHA {index['dataset_sha'][:12]}...
&mdash; {stats['fingerprinted']} packages fingerprinted
({stats.get('skipped', 0)} skipped, {stats.get('errored', 0)} errors)</p>

<h2>TLSH Threshold Explorer</h2>
<p style="color:#666;margin-bottom:12px">Drag the slider to see how different TLSH distance thresholds affect clustering.
At 0 only exact SHA-256 matches are grouped. Higher values merge more similar packages.</p>

<div style="display:flex;align-items:center;gap:16px;margin:16px 0">
  <label style="font-weight:600">Threshold:</label>
  <input type="range" id="thresholdSlider" min="0" max="{len(thresholds)-1}" value="{thresholds.index(current_threshold)}"
         style="width:400px" oninput="updateThreshold(this.value)">
  <span id="thresholdLabel" style="font-size:20px;font-weight:700;min-width:40px">{current_threshold}</span>
</div>

<div class="cards" id="summaryCards"></div>

<h3>Cluster Size Distribution</h3>
<p style="color:#666;margin-bottom:8px">Number of clusters at each size bucket.</p>
<div id="histogram" style="display:flex;gap:4px;align-items:flex-end;padding:12px 0;min-height:240px"></div>

<h3>Top 10 Largest Clusters</h3>
<table id="topClusters">
<tr><th>Size</th><th>Example Packages</th></tr>
</table>

<h2>By Ecosystem</h2>
<table>
<tr><th>Ecosystem</th><th>Packages</th><th>Clusters</th><th>Avg Size</th></tr>
{eco_rows}
</table>

<h2>By Category</h2>
<table>
<tr><th>Category</th><th>Packages</th><th>Clusters</th><th>Avg Size</th></tr>
{cat_rows}
</table>
"""

    slider_js = f"""
const thresholdData = {threshold_data_json};
const bucketLabels = {bucket_labels_json};
const currentDefault = {thresholds.index(current_threshold)};

function updateThreshold(idx) {{
  const d = thresholdData[idx];
  document.getElementById('thresholdLabel').textContent = d.threshold;

  // Summary cards
  const exact = thresholdData[0].total_clusters;
  document.getElementById('summaryCards').innerHTML = `
    <div class="card"><div class="label">Exact Clusters</div><div class="value">${{exact}}</div>
      <div class="sub">SHA-256 only</div></div>
    <div class="card"><div class="label">Final Clusters</div><div class="value">${{d.total_clusters}}</div>
      <div class="sub">with TLSH threshold=${{d.threshold}}</div></div>
    <div class="card"><div class="label">Largest</div><div class="value">${{d.largest}}</div></div>
    <div class="card"><div class="label">Singletons</div><div class="value">${{d.singletons}}</div>
      <div class="sub">${{Math.round(d.singletons * 100 / Math.max(d.total_clusters, 1))}}% of clusters</div></div>
    <div class="card"><div class="label">Dedup Ratio</div><div class="value">${{d.dedup_ratio}}x</div>
      <div class="sub">avg packages/cluster</div></div>
  `;

  // Histogram
  const maxCount = Math.max(...d.buckets, 1);
  let bars = '';
  for (let i = 0; i < d.buckets.length; i++) {{
    const count = d.buckets[i];
    const h = Math.max(2, Math.round((count / maxCount) * 200));
    const color = i === 0 ? '#a5d6a7' : count > 0 ? '#64b5f6' : '#e0e0e0';
    bars += `<div style="display:flex;flex-direction:column;align-items:center;gap:4px">
      <span style="font-size:12px">${{count}}</span>
      <div style="width:48px;height:${{h}}px;background:${{color}};border-radius:4px 4px 0 0;min-height:2px"></div>
      <span style="font-size:11px;color:#666">${{bucketLabels[i]}}</span></div>`;
  }}
  document.getElementById('histogram').innerHTML = bars;

  // Top clusters table
  let rows = '<tr><th>Size</th><th>Example Packages</th></tr>';
  for (const c of d.top_clusters) {{
    rows += `<tr><td>${{c.size}}</td><td class="details">${{c.examples}}</td></tr>`;
  }}
  document.getElementById('topClusters').innerHTML = rows;
}}

// Initialize
updateThreshold(currentDefault);
"""

    html = templates.render("Cluster Index Report", body, extra_css="")
    # Inject the slider JS before the closing </body>
    html = html.replace("</body>", f"<script>\n{slider_js}\n</script>\n</body>")

    out_path = work_dir / "cluster_report.html"
    out_path.write_text(html)
    print(f"Cluster report written to {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    zip_dir = work_dir / "cluster_zips"

    # Phase 1: Enumerate
    dataset_sha, packages = enumerate_packages(args.ecosystems, args.dataset_path)

    # Phase 2: Resolve ZIP paths
    packages = resolve_all_zip_paths(packages, args.dataset_path, dataset_sha,
                                     args.ecosystems, args.workers)

    # Phase 3: Download ZIPs
    pkg_to_zip = download_all_zips(
        packages, zip_dir, dataset_sha, args.dataset_path, args.max_zip_size, args.workers)

    # Phase 4: Fingerprint
    guarddog_bin = find_guarddog_bin()
    print(f"Using guarddog: {guarddog_bin}")
    fingerprint_results = fingerprint_all(
        packages, pkg_to_zip, guarddog_bin, args.workers, args.timeout, args.no_sandbox)

    # Phase 3b: Detect empty ZIPs
    empty_packages = find_empty_packages(pkg_to_zip, args.workers)

    # Phase 5: Build index (SHA-256 exact + TLSH fuzzy merging)
    index = build_cluster_index(dataset_sha, packages, fingerprint_results,
                                args.max_zip_size, args.tlsh_threshold,
                                empty_packages=empty_packages)

    CLUSTER_INDEX_FILE.write_text(json.dumps(index, indent=2))
    print(f"\nCluster index written to {CLUSTER_INDEX_FILE}")

    print_summary(index)
    build_cluster_report(index, work_dir)


if __name__ == "__main__":
    main()
