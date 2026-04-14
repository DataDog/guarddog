#!/usr/bin/env python3
"""
GuardDog Recall Benchmark

Measures detection rate on known-malicious packages from the
DataDog malicious-software-packages-dataset.

Each package is extracted and scanned inside a Nono sandbox subprocess
with no network access. Extracted files are deleted after each scan.

Usage:
    uv run evals/recall.py
    uv run evals/recall.py --ecosystems pypi --workers 5
    uv run evals/recall.py --phase report
    uv run evals/recall.py --regenerate-samples
"""

import argparse
import concurrent.futures
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from evals import templates


EVALS_DIR = Path(__file__).parent
DEFAULT_WORK_DIR = EVALS_DIR / "workdir"
SAMPLES_FILE = EVALS_DIR / "recall_samples.json"
CLUSTER_INDEX_FILE = EVALS_DIR / "cluster_index.json"
WORKER_SCRIPT = EVALS_DIR / "recall_worker.py"


def parse_args():
    p = argparse.ArgumentParser(description="GuardDog Recall Benchmark")
    p.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    p.add_argument("--phase", choices=["all", "fetch", "scan", "report"], default="all")
    p.add_argument("--ecosystems", nargs="+", choices=["pypi", "npm"], default=["pypi", "npm"])
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--dataset-path", type=Path, default=None,
                   help="Path to local clone of malicious-software-packages-dataset")
    p.add_argument("--regenerate-samples", action="store_true",
                   help="Regenerate recall_samples.json from the dataset")
    p.add_argument("--samples-per-ecosystem", type=int, default=250,
                   help="Total samples per ecosystem (compromised_lib first, then malicious_intent)")
    p.add_argument("--seed", type=str, default=None,
                   help="Hex seed for sampling (default: random). Printed on generation for reproducibility.")
    p.add_argument("--max-per-cluster", type=int, default=3,
                   help="Max packages per duplicate cluster (0=no dedup, requires cluster_index.json)")
    p.add_argument("--no-sandbox", action="store_true",
                   help="Skip Nono sandbox (DANGEROUS, for testing only)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Sample generation (--regenerate-samples)
# ---------------------------------------------------------------------------

def _load_cluster_index() -> dict | None:
    """Load cluster_index.json if it exists."""
    if CLUSTER_INDEX_FILE.exists():
        try:
            return json.loads(CLUSTER_INDEX_FILE.read_text())
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _cluster_aware_sample(
    package_names: list[str],
    cluster_index: dict,
    ecosystem: str,
    category: str,
    max_per_cluster: int,
    budget: int,
    rng,
) -> list[str]:
    """Sample packages respecting cluster limits.

    Round-robin across clusters: every cluster gets 1 representative first,
    then 2, etc., up to max_per_cluster. This ensures every unique malware
    family is represented before any gets over-represented.
    """
    # Group by cluster fingerprint
    fingerprints = cluster_index.get("fingerprints", {})
    cluster_map = defaultdict(list)
    for pkg in package_names:
        key = f"{ecosystem}/{category}/{pkg}"
        fp = fingerprints.get(key)
        if fp:
            cluster_map[fp].append(pkg)
        else:
            cluster_map[f"__unknown__{pkg}"].append(pkg)

    # Shuffle within each cluster for randomness
    for pkgs in cluster_map.values():
        rng.shuffle(pkgs)

    cluster_list = list(cluster_map.values())
    rng.shuffle(cluster_list)

    # Round-robin: take 1 from each cluster, then 2, up to max_per_cluster
    selected = []
    for round_num in range(max_per_cluster):
        if len(selected) >= budget:
            break
        for cluster_pkgs in cluster_list:
            if len(selected) >= budget:
                break
            if round_num < len(cluster_pkgs):
                selected.append(cluster_pkgs[round_num])

    return selected


def _get_cluster_id(package: str, ecosystem: str, category: str, cluster_index: dict | None) -> str | None:
    """Look up the cluster fingerprint for a package."""
    if not cluster_index:
        return None
    key = f"{ecosystem}/{category}/{package}"
    return cluster_index.get("fingerprints", {}).get(key)


def regenerate_samples(ecosystems: list[str], samples_per_eco: int, seed: str | None,
                       max_per_cluster: int = 3):
    """Fetch manifests from GitHub and generate a new recall_samples.json.

    Prioritizes compromised_lib packages (up to half the budget), then fills
    the rest with malicious_intent. compromised_lib are supply chain attacks
    and are rare/high-value so they always get priority.

    If cluster_index.json exists and max_per_cluster > 0, uses cluster-aware
    sampling to limit how many packages are drawn from each duplicate cluster.
    """
    import random
    if seed is None:
        seed = secrets.token_hex(8)
    random.seed(seed)

    # Load cluster index for deduplication and empty-package filtering
    cluster_index = None
    empty_packages_set = set()
    if max_per_cluster > 0:
        cluster_index = _load_cluster_index()
        if cluster_index:
            stats = cluster_index.get("stats", {})
            empty_packages_set = set(cluster_index.get("empty_packages", []))
            print(f"Loaded cluster index: {stats.get('total_clusters', '?')} clusters, "
                  f"max {max_per_cluster} per cluster"
                  f"{f', {len(empty_packages_set)} empty packages excluded' if empty_packages_set else ''}")
        else:
            print("WARNING: No cluster_index.json found. Run 'uv run evals/cluster.py' first.")
            print("  Falling back to random sampling without deduplication.")

    print(f"Fetching manifests from GitHub (seed={seed})...")
    repo = "DataDog/malicious-software-packages-dataset"

    sha = _github_api(f"repos/{repo}/commits/main")["sha"]
    print(f"  Dataset SHA: {sha}")

    samples = []
    for eco in ecosystems:
        manifest_url = f"https://raw.githubusercontent.com/{repo}/main/samples/{eco}/manifest.json"
        manifest = _fetch_json(manifest_url)

        compromised = sorted([k for k, v in manifest.items() if v is not None])
        malicious = sorted([k for k, v in manifest.items() if v is None])

        if empty_packages_set:
            compromised = [p for p in compromised
                           if f"{eco}/compromised_lib/{p}" not in empty_packages_set]
            malicious = [p for p in malicious
                         if f"{eco}/malicious_intent/{p}" not in empty_packages_set]

        available_total = len(compromised) + len(malicious)
        if samples_per_eco > available_total:
            print(f"  WARNING: requested {samples_per_eco} samples for {eco} but only "
                  f"{available_total} available ({len(compromised)} compromised + "
                  f"{len(malicious)} malicious_intent). Taking all.")

        # Compromised_lib first, capped at half the budget
        n_comp = min(len(compromised), samples_per_eco // 2)
        if cluster_index and max_per_cluster > 0:
            compromised_selected = _cluster_aware_sample(
                compromised, cluster_index, eco, "compromised_lib",
                max_per_cluster, n_comp, random)
        else:
            random.shuffle(compromised)
            compromised_selected = compromised[:n_comp]

        for pkg in compromised_selected:
            cluster_id = _get_cluster_id(pkg, eco, "compromised_lib", cluster_index)
            entry = {"package": pkg, "ecosystem": eco, "category": "compromised_lib"}
            if cluster_id:
                entry["cluster_id"] = cluster_id
            samples.append(entry)

        # Fill the rest with malicious_intent
        remaining = min(samples_per_eco - len(compromised_selected), len(malicious))
        if cluster_index and max_per_cluster > 0:
            malicious_selected = _cluster_aware_sample(
                malicious, cluster_index, eco, "malicious_intent",
                max_per_cluster, remaining, random)
        else:
            random.shuffle(malicious)
            malicious_selected = malicious[:remaining]

        for pkg in malicious_selected:
            cluster_id = _get_cluster_id(pkg, eco, "malicious_intent", cluster_index)
            entry = {"package": pkg, "ecosystem": eco, "category": "malicious_intent"}
            if cluster_id:
                entry["cluster_id"] = cluster_id
            samples.append(entry)

        n_comp_actual = len(compromised_selected)
        n_mal_actual = len(malicious_selected)
        n_clusters = len(set(
            _get_cluster_id(pkg, eco, "malicious_intent", cluster_index) or pkg
            for pkg in malicious_selected
        ))
        cluster_info = f" ({n_clusters} unique clusters)" if cluster_index else ""
        print(f"  {eco}: {n_mal_actual} malicious_intent{cluster_info} + {n_comp_actual} compromised_lib "
              f"= {n_comp_actual + n_mal_actual}/{samples_per_eco} requested "
              f"(dataset has {len(malicious)} malicious + {len(compromised)} compromised)")

    # Resolve ZIP paths in parallel
    print(f"Resolving ZIP paths for {len(samples)} samples (parallel)...")
    resolved = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_idx = {
            executor.submit(_resolve_zip_path, repo, s): i
            for i, s in enumerate(samples)
        }
        done = 0
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            samples[idx]["zip_path"] = future.result()
            if samples[idx]["zip_path"]:
                resolved += 1
            done += 1
            if done % 100 == 0 or done == len(samples):
                print(f"  [{done}/{len(samples)}] {resolved} resolved")

    samples = [s for s in samples if s.get("zip_path")]
    result = {
        "dataset_sha": sha,
        "dataset_repo": repo,
        "seed": seed,
        "samples_per_ecosystem": samples_per_eco,
        "max_per_cluster": max_per_cluster if cluster_index else None,
        "samples": samples,
    }
    SAMPLES_FILE.write_text(json.dumps(result, indent=2))
    print(f"Wrote {len(samples)} samples to {SAMPLES_FILE}")
    print(f"  Seed: {seed} (pass --seed {seed} to reproduce this exact sample)")


def _github_headers() -> dict:
    headers = {"User-Agent": "guarddog-evals/1.0", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers=_github_headers())
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _github_api(endpoint: str) -> dict | list:
    return _fetch_json(f"https://api.github.com/{endpoint}")


def _resolve_zip_path(repo: str, sample: dict) -> str | None:
    """Find the latest ZIP path for a sample package via GitHub API."""
    import urllib.parse
    pkg = sample["package"]
    eco = sample["ecosystem"]
    cat = sample["category"]
    dir_path = f"samples/{eco}/{cat}/{pkg}"
    encoded_path = urllib.parse.quote(dir_path, safe="/")

    try:
        entries = _github_api(f"repos/{repo}/contents/{encoded_path}")
        versions = sorted([e["name"] for e in entries if e["type"] == "dir"])
        if not versions:
            return None
        version = versions[-1]

        version_path = urllib.parse.quote(f"{dir_path}/{version}", safe="/")
        files = _github_api(f"repos/{repo}/contents/{version_path}")
        zips = [f["path"] for f in files if f["name"].endswith(".zip")]
        return zips[0] if zips else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Phase 1: Fetch ZIPs
# ---------------------------------------------------------------------------

def run_fetch(work_dir: Path, ecosystems: list[str], dataset_path: Path | None):
    if not SAMPLES_FILE.exists():
        sys.exit(f"ERROR: {SAMPLES_FILE} not found. Run --regenerate-samples first.")

    data = json.loads(SAMPLES_FILE.read_text())
    samples = [s for s in data["samples"] if s["ecosystem"] in ecosystems]
    sha = data["dataset_sha"]
    repo = data["dataset_repo"]

    zip_dir = work_dir / "malicious_zips"
    zip_dir.mkdir(parents=True, exist_ok=True)

    print(f"Fetching {len(samples)} sample ZIPs...")
    fetched = 0
    skipped = 0

    for i, sample in enumerate(samples):
        safe_name = sample["package"].replace("@", "_at_").replace("/", "__")
        local_zip = zip_dir / sample["ecosystem"] / f"{safe_name}.zip"

        if local_zip.exists():
            skipped += 1
            continue

        if dataset_path:
            src = dataset_path / sample["zip_path"]
            if src.exists():
                local_zip.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, local_zip)
                fetched += 1
                continue

        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{sample['zip_path']}"
        try:
            local_zip.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(url, headers={"User-Agent": "guarddog-evals/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                local_zip.write_bytes(resp.read())
            fetched += 1
        except Exception as e:
            print(f"  WARN: failed to fetch {sample['package']}: {e}")

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(samples)}] {fetched} fetched, {skipped} cached")

    print(f"Done. {fetched} fetched, {skipped} cached.")


# ---------------------------------------------------------------------------
# Phase 2: Scan (sandboxed workers)
# ---------------------------------------------------------------------------

def find_guarddog_bin() -> str:
    """Find the guarddog binary, preferring the project .venv."""
    venv_bin = EVALS_DIR.parent / ".venv" / "bin" / "guarddog"
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which("guarddog")
    if found:
        return found
    sys.exit("ERROR: guarddog not found. Run 'uv pip install -e .' from the repo root first.")


def scan_single(sample: dict, work_dir: Path, guarddog_bin: str, timeout: int, no_sandbox: bool) -> dict:
    safe_name = sample["package"].replace("@", "_at_").replace("/", "__")
    zip_path = work_dir / "malicious_zips" / sample["ecosystem"] / f"{safe_name}.zip"
    result_dir = work_dir / "recall_results" / sample["ecosystem"]
    result_dir.mkdir(parents=True, exist_ok=True)
    result_file = result_dir / f"{safe_name}.json"

    if result_file.exists():
        try:
            return json.loads(result_file.read_text())
        except (json.JSONDecodeError, ValueError):
            pass

    result = {"package": sample["package"], "ecosystem": sample["ecosystem"],
              "category": sample["category"], "error": None, "scan_output": None}

    if not zip_path.exists():
        result["error"] = "ZIP not found"
        result_file.write_text(json.dumps(result, indent=2))
        return result

    # Create temp file for worker output
    tmp_base = os.path.realpath(tempfile.gettempdir())
    output_fd, output_path = tempfile.mkstemp(dir=tmp_base, suffix=".json", prefix="gd_recall_")
    os.close(output_fd)

    # Delegate to recall_worker.py which runs inside a Nono sandbox
    cmd = [
        sys.executable, str(WORKER_SCRIPT),
        "--zip-path", str(zip_path.resolve()),
        "--ecosystem", sample["ecosystem"],
        "--output-path", output_path,
        "--guarddog-bin", guarddog_bin,
    ]
    if no_sandbox:
        cmd.append("--no-sandbox")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              cwd=str(EVALS_DIR.parent))
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path) as f:
                worker_result = json.load(f)
            result["scan_output"] = worker_result.get("results")
            if worker_result.get("error"):
                result["error"] = worker_result["error"]
        elif proc.returncode != 0:
            result["error"] = f"Worker exit {proc.returncode}: {proc.stderr[:500]}"
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except Exception as e:
        result["error"] = str(e)[:500]
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass

    result_file.write_text(json.dumps(result, indent=2))
    return result


def run_scan(work_dir: Path, ecosystems: list[str], workers: int, timeout: int, no_sandbox: bool):
    data = json.loads(SAMPLES_FILE.read_text())
    samples = [s for s in data["samples"] if s["ecosystem"] in ecosystems]
    total = len(samples)
    completed = 0
    errors = 0
    start = time.time()
    guarddog_bin = find_guarddog_bin()
    print(f"Using guarddog: {guarddog_bin}")
    print(f"Scanning {total} malicious packages with {workers} workers (timeout {timeout}s)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for sample in samples:
            fut = executor.submit(scan_single, sample, work_dir, guarddog_bin, timeout, no_sandbox)
            futures[fut] = sample

        for fut in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                res = fut.result()
                if res.get("error"):
                    errors += 1
            except Exception:
                errors += 1

            if completed % 25 == 0 or completed == total:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total - completed) / rate if rate > 0 else 0
                print(f"  [{completed}/{total}] {errors} errors | {elapsed:.0f}s | ETA {eta:.0f}s")

    print(f"Done. {completed} scans, {errors} errors, {time.time() - start:.0f}s total.")


# ---------------------------------------------------------------------------
# Phase 3: Report
# ---------------------------------------------------------------------------

def has_findings(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (dict, list)):
        return len(value) > 0
    if isinstance(value, str):
        return len(value.strip()) > 0
    return bool(value)


def run_report(work_dir: Path, ecosystems: list[str]):
    print("Generating recall report...")
    results_dir = work_dir / "recall_results"
    results = []
    for eco in ecosystems:
        d = results_dir / eco
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix == ".json":
                try:
                    results.append(json.loads(f.read_text()))
                except (json.JSONDecodeError, ValueError):
                    pass

    if not results:
        sys.exit("No results found. Run --phase scan first.")

    # Analyze
    total = len(results)
    scan_errors = sum(1 for r in results if r.get("error"))
    successful = total - scan_errors

    detected_any = 0  # at least one rule fired
    detected_rules = defaultdict(int)
    score_buckets = defaultdict(int)
    scores_all = []
    pkg_rows = []

    for r in results:
        out = r.get("scan_output") or {}
        scan_results = out.get("results", {})
        fired = [k for k, v in scan_results.items() if has_findings(v)]
        is_detected = len(fired) > 0 or out.get("issues", 0) > 0

        risk = out.get("risk_score") or {}
        score = risk.get("score")
        label = risk.get("label")

        if is_detected:
            detected_any += 1
        for rule in fired:
            detected_rules[rule] += 1

        if score is not None and not r.get("error"):
            scores_all.append(score)
            bucket = min(int(score), 9)
            score_buckets[bucket] += 1

        pkg_rows.append({
            "name": r["package"], "ecosystem": r["ecosystem"],
            "category": r.get("category", "unknown"),
            "detected": is_detected, "rules_fired": len(fired),
            "rules": fired, "error": r.get("error"),
            "score": score, "risk_label": label,
        })

    recall_rate = detected_any / successful * 100 if successful else 0
    missed = [p for p in pkg_rows if not p["detected"] and not p["error"]]

    # Score stats
    avg_score = sum(scores_all) / len(scores_all) if scores_all else 0
    median_score = sorted(scores_all)[len(scores_all) // 2] if scores_all else 0
    max_score = max(scores_all) if scores_all else 0

    # Risk label distribution
    risk_dist = defaultdict(int)
    for p in pkg_rows:
        if p["error"]:
            risk_dist["error"] += 1
        elif p["risk_label"]:
            risk_dist[p["risk_label"].lower()] += 1
        else:
            risk_dist["none"] += 1

    # Per-ecosystem score stats
    eco_score_buckets = {eco: defaultdict(int) for eco in ecosystems}
    for p in pkg_rows:
        if p["score"] is not None and not p["error"]:
            eco_score_buckets[p["ecosystem"]][min(int(p["score"]), 9)] += 1

    # Per-ecosystem stats
    eco_stats = {}
    for eco in ecosystems:
        eco_pkgs = [p for p in pkg_rows if p["ecosystem"] == eco]
        eco_ok = [p for p in eco_pkgs if not p["error"]]
        eco_det = sum(1 for p in eco_ok if p["detected"])
        eco_scores = [p["score"] for p in eco_ok if p["score"] is not None]
        eco_stats[eco] = {
            "total": len(eco_pkgs), "successful": len(eco_ok),
            "detected": eco_det,
            "recall": eco_det / len(eco_ok) * 100 if eco_ok else 0,
            "errors": sum(1 for p in eco_pkgs if p["error"]),
            "avg_score": sum(eco_scores) / len(eco_scores) if eco_scores else 0,
            "median_score": sorted(eco_scores)[len(eco_scores) // 2] if eco_scores else 0,
        }

    # Per-category stats
    cat_stats = {}
    for cat in ["malicious_intent", "compromised_lib"]:
        cat_pkgs = [p for p in pkg_rows if p["category"] == cat]
        cat_ok = [p for p in cat_pkgs if not p["error"]]
        cat_det = sum(1 for p in cat_ok if p["detected"])
        cat_scores = [p["score"] for p in cat_ok if p["score"] is not None]
        cat_stats[cat] = {
            "total": len(cat_pkgs), "successful": len(cat_ok),
            "detected": cat_det,
            "recall": cat_det / len(cat_ok) * 100 if cat_ok else 0,
            "avg_score": sum(cat_scores) / len(cat_scores) if cat_scores else 0,
            "median_score": sorted(cat_scores)[len(cat_scores) // 2] if cat_scores else 0,
        }

    # Cluster-level recall (if cluster_index.json is available)
    cluster_stats = None
    samples_data = json.loads(SAMPLES_FILE.read_text()) if SAMPLES_FILE.exists() else {}
    sample_clusters = {s["package"]: s.get("cluster_id") for s in samples_data.get("samples", [])}
    has_clusters = any(sample_clusters.values())

    if has_clusters:
        cluster_results = defaultdict(list)
        for p in pkg_rows:
            cid = sample_clusters.get(p["name"], p["name"])
            cluster_results[cid].append(p)

        clusters_total = len(cluster_results)
        clusters_ok = {cid: pkgs for cid, pkgs in cluster_results.items()
                       if any(not p["error"] for p in pkgs)}
        clusters_detected = sum(
            1 for pkgs in clusters_ok.values()
            if any(p["detected"] for p in pkgs)
        )
        cluster_recall = clusters_detected / len(clusters_ok) * 100 if clusters_ok else 0
        cluster_stats = {
            "total": clusters_total,
            "successful": len(clusters_ok),
            "detected": clusters_detected,
            "recall": cluster_recall,
        }

    top_rules = sorted(detected_rules.items(), key=lambda x: -x[1])
    html = build_recall_html(
        total=total, successful=successful, detected=detected_any,
        recall_rate=recall_rate, scan_errors=scan_errors,
        avg_score=avg_score, median_score=median_score, max_score=max_score,
        score_buckets=dict(score_buckets), eco_score_buckets=eco_score_buckets,
        risk_dist=dict(risk_dist),
        ecosystems=ecosystems, eco_stats=eco_stats, cat_stats=cat_stats,
        cluster_stats=cluster_stats,
        top_rules=top_rules, missed=missed, pkg_rows=pkg_rows,
    )

    out_path = work_dir / "recall_report.html"
    out_path.write_text(html)
    print(f"Report written to {out_path}")

    print(f"\n{'='*60}")
    print(f"  Packages scanned: {total} ({successful} successful, {scan_errors} errors)")
    print(f"  Detected: {detected_any}/{successful} ({recall_rate:.1f}%)")
    print(f"  Missed: {len(missed)}")
    print(f"  Score: avg={avg_score:.2f}  median={median_score:.1f}  max={max_score:.1f}")
    for eco in ecosystems:
        s = eco_stats[eco]
        print(f"  {eco.upper()}: {s['detected']}/{s['successful']} ({s['recall']:.1f}%) "
              f"avg={s['avg_score']:.2f} median={s['median_score']:.1f}")
    for cat, s in cat_stats.items():
        print(f"  {cat}: {s['detected']}/{s['successful']} ({s['recall']:.1f}%)")
    if cluster_stats:
        cs = cluster_stats
        print(f"  Cluster-level recall: {cs['detected']}/{cs['successful']} ({cs['recall']:.1f}%)")
    print(f"{'='*60}")


def build_recall_html(*, total, successful, detected, recall_rate, scan_errors,
                      avg_score, median_score, max_score, score_buckets,
                      eco_score_buckets, risk_dist,
                      ecosystems, eco_stats, cat_stats, cluster_stats,
                      top_rules, missed, pkg_rows):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    eco_rows = ""
    for eco in ecosystems:
        s = eco_stats[eco]
        eco_rows += (f"<tr><td>{escape(eco.upper())}</td><td>{s['total']}</td>"
                     f"<td>{s['successful']}</td><td>{s['detected']}</td>"
                     f"<td><b>{s['recall']:.1f}%</b></td>"
                     f"<td>{s['avg_score']:.1f}</td><td>{s['median_score']:.1f}</td>"
                     f"<td>{s['errors']}</td></tr>\n")

    cat_rows = ""
    for cat, s in cat_stats.items():
        cat_rows += (f"<tr><td>{escape(cat)}</td><td>{s['total']}</td>"
                     f"<td>{s['successful']}</td><td>{s['detected']}</td>"
                     f"<td><b>{s['recall']:.1f}%</b></td>"
                     f"<td>{s['avg_score']:.1f}</td><td>{s['median_score']:.1f}</td></tr>\n")

    cluster_section = ""
    if cluster_stats:
        cs = cluster_stats
        cluster_section = f"""
<h2>Cluster-Level Recall</h2>
<p style="color:#666;margin-bottom:8px">A cluster groups packages with identical/similar malicious code.
Cluster recall measures how many distinct malware families are detected (at least one package in the cluster detected).</p>
<div class="cards">
  <div class="card"><div class="label">Clusters</div><div class="value">{cs['successful']}</div></div>
  <div class="card"><div class="label">Detected</div>
    <div class="value {'green' if cs['recall'] > 80 else 'red'}">{cs['detected']}</div>
    <div class="sub">{cs['recall']:.1f}% cluster recall</div></div>
  <div class="card"><div class="label">Missed Families</div>
    <div class="value {'green' if cs['successful'] - cs['detected'] < 10 else 'red'}">{cs['successful'] - cs['detected']}</div></div>
</div>"""

    # Inverted colors for malicious: low scores are bad (red), high scores are good (green)
    inv = {"low_color": "#ef5350", "mid_color": "#fff176", "high_color": "#a5d6a7"}

    eco_hist = ""
    for eco in ecosystems:
        eco_hist += (f'<div><h3>{escape(eco.upper())}</h3>'
                     f'{templates.score_histogram(eco_score_buckets[eco], max_height=150, bar_width=32, **inv)}</div>\n')

    rules_html = ""
    for rule, count in top_rules[:30]:
        pct = count / successful * 100 if successful else 0
        bar_w = int(pct * 2)
        rules_html += (f"<tr><td>{escape(rule)}</td><td>{count}</td>"
                       f"<td><div style='display:flex;align-items:center;gap:8px'>"
                       f"<div style='width:{bar_w}px;height:14px;background:#1976d2;border-radius:2px'></div>"
                       f"{pct:.1f}%</div></td></tr>\n")

    missed_html = ""
    for p in sorted(missed, key=lambda x: x["name"]):
        missed_html += (f"<tr><td>{escape(p['name'])}</td><td>{escape(p['ecosystem'].upper())}</td>"
                        f"<td>{escape(p['category'])}</td></tr>\n")

    pkg_rows_html = ""
    for p in sorted(pkg_rows, key=lambda x: (x.get("score") is None, -(x.get("score") or 0), x["name"])):
        status = "err" if p["error"] else ("yes" if p["detected"] else "NO")
        bg = "#ffcdd2" if not p["detected"] and not p["error"] else ""
        score_s = f"{p['score']:.1f}" if p.get("score") is not None else "-"
        label_s = p.get("risk_label") or "-"
        rules = escape(", ".join(p["rules"])) if p["rules"] else "-"
        pkg_rows_html += (f"<tr class='pkg-row' data-eco='{p['ecosystem']}' "
                          f"data-detected='{'yes' if p['detected'] else 'no'}' "
                          f"data-name='{escape(p['name'].lower())}' style='background:{bg}'>"
                          f"<td>{escape(p['name'])}</td><td>{escape(p['ecosystem'].upper())}</td>"
                          f"<td>{escape(p['category'])}</td><td><b>{status}</b></td>"
                          f"<td>{score_s}</td><td>{label_s}</td>"
                          f"<td>{p['rules_fired']}</td>"
                          f"<td class='details'>{rules}</td></tr>\n")

    body = f"""
<h1>GuardDog Recall Benchmark</h1>
<p class="meta">Generated {ts} &mdash; {total} known-malicious packages from DataDog/malicious-software-packages-dataset</p>

<div class="cards">
  <div class="card"><div class="label">Packages Scanned</div><div class="value">{successful}</div>
    <div class="sub">{scan_errors} errors</div></div>
  <div class="card"><div class="label">Detected</div><div class="value {'green' if recall_rate > 80 else 'red'}">{detected}</div>
    <div class="sub">{recall_rate:.1f}% recall</div></div>
  <div class="card"><div class="label">Missed</div><div class="value {'green' if len(missed) < 20 else 'red'}">{len(missed)}</div>
    <div class="sub">false negatives</div></div>
  <div class="card"><div class="label">Avg Score</div><div class="value">{avg_score:.1f}</div></div>
  <div class="card"><div class="label">Median Score</div><div class="value">{median_score:.1f}</div></div>
</div>

<h2>Recall by Ecosystem</h2>
<table>
<tr><th>Ecosystem</th><th>Total</th><th>Scanned</th><th>Detected</th><th>Recall</th><th>Avg Score</th><th>Median Score</th><th>Errors</th></tr>
{eco_rows}
</table>

<h2>Recall by Category</h2>
<table>
<tr><th>Category</th><th>Total</th><th>Scanned</th><th>Detected</th><th>Recall</th><th>Avg Score</th><th>Median Score</th></tr>
{cat_rows}
</table>

{cluster_section}

<h2>Risk Score Distribution</h2>
<p style="color:#666;margin-bottom:8px">On malicious packages, higher scores = better detection. Red bars (low scores) indicate missed or under-scored packages.</p>
<h3>All Ecosystems</h3>
{templates.score_histogram(score_buckets, **inv)}
<div class="two-col">{eco_hist}</div>

<h2>Risk Label Distribution</h2>
{templates.risk_label_bars(risk_dist)}

<h2>Top Triggered Rules on Malicious Packages</h2>
<table id="rulesTable">
<tr><th onclick="sortTable('rulesTable',0)">Rule</th>
<th onclick="sortTable('rulesTable',1)">Detections</th>
<th onclick="sortTable('rulesTable',2)">% of Scanned</th></tr>
{rules_html}
</table>

<h2>False Negatives (Missed Packages)</h2>
<p style="color:#666;margin-bottom:8px">Packages that were scanned successfully but triggered zero rules.</p>
<table>
<tr><th>Package</th><th>Ecosystem</th><th>Category</th></tr>
{missed_html if missed_html else "<tr><td colspan='3'>None! All packages detected.</td></tr>"}
</table>

<h2>Per-Package Details</h2>
<div class="filters">
  <input type="text" id="pkgSearch" placeholder="Filter by package name..." oninput="filterPkgs()">
  <select id="ecoFilter" onchange="filterPkgs()">
    <option value="">All ecosystems</option>
    {templates.eco_filter_options(ecosystems)}
  </select>
  <select id="detFilter" onchange="filterPkgs()">
    <option value="">All</option>
    <option value="yes">Detected</option>
    <option value="no">Missed</option>
  </select>
</div>
<table id="pkgTable">
<tr><th onclick="sortTable('pkgTable',0)">Package</th>
<th onclick="sortTable('pkgTable',1)">Ecosystem</th>
<th onclick="sortTable('pkgTable',2)">Category</th>
<th onclick="sortTable('pkgTable',3)">Detected</th>
<th onclick="sortTable('pkgTable',4)">Score</th>
<th onclick="sortTable('pkgTable',5)">Label</th>
<th onclick="sortTable('pkgTable',6)">Rules Fired</th>
<th>Rules</th></tr>
{pkg_rows_html}
</table>"""

    return templates.render("GuardDog Recall Benchmark", body)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if args.regenerate_samples:
        regenerate_samples(args.ecosystems, args.samples_per_ecosystem, args.seed,
                           args.max_per_cluster)
        return

    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    phase = args.phase

    if phase in ("all", "fetch"):
        run_fetch(work_dir, args.ecosystems, args.dataset_path)
    if phase in ("all", "scan"):
        run_scan(work_dir, args.ecosystems, args.workers, args.timeout, args.no_sandbox)
    if phase in ("all", "report"):
        run_report(work_dir, args.ecosystems)


if __name__ == "__main__":
    main()
