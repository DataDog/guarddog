#!/usr/bin/env python3
"""
GuardDog Evaluation Benchmark

Scans the top N most-popular PyPI and NPM packages with guarddog and generates
an HTML report of score distributions, rule trigger rates, and per-package details.

Usage:
    uv run evals/benchmark.py
    uv run evals/benchmark.py --max-packages 50 --ecosystems pypi
    uv run evals/benchmark.py --phase report
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from evals import templates


EVALS_DIR = Path(__file__).parent
DEFAULT_WORK_DIR = EVALS_DIR / "workdir"


def parse_args():
    p = argparse.ArgumentParser(description="GuardDog Evaluation Benchmark")
    p.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    p.add_argument("--phase", choices=["all", "fetch", "scan", "report"], default="all")
    p.add_argument("--ecosystems", nargs="+", choices=["pypi", "npm"], default=["pypi", "npm"])
    p.add_argument("--max-packages", type=int, default=1000)
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--force-fetch", action="store_true")
    p.add_argument("--guarddog-bin", default=None, help="Path to guarddog binary")
    return p.parse_args()


def find_guarddog_bin(override: str | None) -> str:
    if override:
        return override
    found = shutil.which("guarddog")
    if found:
        return found
    sys.exit("ERROR: guarddog not found on PATH. Install it or pass --guarddog-bin")


# ---------------------------------------------------------------------------
# Phase 1: Fetch
# ---------------------------------------------------------------------------

def fetch_pypi(max_packages: int) -> list[dict]:
    print(f"Fetching top {max_packages} PyPI packages...")
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    req = urllib.request.Request(url, headers={"User-Agent": "guarddog-evals/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    packages = [{"name": row["project"]} for row in data["rows"][:max_packages]]
    print(f"  Got {len(packages)} PyPI packages")
    return packages


def fetch_npm(max_packages: int) -> list[dict]:
    print(f"Fetching top {max_packages} NPM packages...")
    packages = []
    page_size = 250
    for offset in range(0, max_packages, page_size):
        size = min(page_size, max_packages - len(packages))
        url = f"https://api.npms.io/v2/search?q=not:unstable&size={size}&from={offset}"
        req = urllib.request.Request(url, headers={"User-Agent": "guarddog-evals/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        batch = [{"name": obj["package"]["name"]} for obj in data.get("results", [])]
        packages.extend(batch)
        print(f"  Fetched {len(packages)} NPM packages...")
        if len(batch) < size:
            break
    packages = packages[:max_packages]
    print(f"  Got {len(packages)} NPM packages")
    return packages


def run_fetch(work_dir: Path, ecosystems: list[str], max_packages: int, force: bool):
    data_dir = work_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    fetchers = {"pypi": fetch_pypi, "npm": fetch_npm}
    for eco in ecosystems:
        path = data_dir / f"{eco}_packages.json"
        if path.exists() and not force:
            print(f"Skipping fetch for {eco} (cached at {path})")
            continue
        packages = fetchers[eco](max_packages)
        path.write_text(json.dumps(packages, indent=2))


# ---------------------------------------------------------------------------
# Phase 2: Scan
# ---------------------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    return name.replace("@", "_at_").replace("/", "__")


def scan_package(package: str, ecosystem: str, gd_bin: str,
                 results_dir: Path, timeout: int) -> dict:
    safe = sanitize_filename(package)
    out_dir = results_dir / ecosystem
    out_dir.mkdir(parents=True, exist_ok=True)
    result_file = out_dir / f"{safe}.json"

    if result_file.exists():
        return json.loads(result_file.read_text())

    result = {"package": package, "ecosystem": ecosystem,
              "scan_time": None, "error": None, "output": None}

    cmd = [gd_bin, ecosystem, "scan", package, "--output-format", "json"]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result["scan_time"] = round(time.time() - start, 2)
        stdout = proc.stdout.strip()
        if not stdout:
            result["error"] = f"Exit {proc.returncode}: {proc.stderr[:500]}"
        else:
            try:
                result["output"] = json.loads(stdout)
            except json.JSONDecodeError:
                result["error"] = f"Invalid JSON: {stdout[:500]}"
    except subprocess.TimeoutExpired:
        result["scan_time"] = timeout
        result["error"] = f"Timeout after {timeout}s"
    except Exception as e:
        result["error"] = str(e)

    result_file.write_text(json.dumps(result, indent=2))
    return result


def run_scan(work_dir: Path, ecosystems: list[str], gd_bin: str,
             workers: int, timeout: int):
    results_dir = work_dir / "results"

    tasks = []
    for eco in ecosystems:
        pkg_file = work_dir / "data" / f"{eco}_packages.json"
        if not pkg_file.exists():
            sys.exit(f"ERROR: {pkg_file} not found. Run --phase fetch first.")
        packages = json.loads(pkg_file.read_text())
        for pkg in packages:
            tasks.append((pkg["name"], eco))

    total = len(tasks)
    completed = 0
    errors = 0
    start_all = time.time()

    print(f"Scanning {total} packages with {workers} workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for name, eco in tasks:
            fut = executor.submit(scan_package, name, eco, gd_bin, results_dir, timeout)
            futures[fut] = (name, eco)

        for fut in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                res = fut.result()
                if res.get("error"):
                    errors += 1
            except Exception:
                errors += 1

            if completed % 100 == 0 or completed == total:
                elapsed = time.time() - start_all
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total - completed) / rate if rate > 0 else 0
                print(f"  [{completed}/{total}] {errors} errors | "
                      f"{elapsed:.0f}s elapsed | ETA {eta:.0f}s")

    print(f"Done. {completed} scans, {errors} errors, {time.time() - start_all:.0f}s total.")


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


def load_results(work_dir: Path, ecosystems: list[str]) -> list[dict]:
    results = []
    results_dir = work_dir / "results"
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
    return results


def run_report(work_dir: Path, ecosystems: list[str]):
    print("Generating report...")
    results = load_results(work_dir, ecosystems)
    if not results:
        sys.exit("No results found. Run --phase scan first.")

    # Detect guarddog version from first result
    gd_version = None
    for r in results:
        out = r.get("output") or {}
        if out.get("risk_score"):
            gd_version = "v3 (risk scoring)"
            break
    if not gd_version:
        gd_version = "unknown"

    pkg_summaries = []
    rule_counts = defaultdict(int)
    total_errors = 0

    for r in results:
        row = {"name": r["package"], "ecosystem": r["ecosystem"],
               "risk_score": None, "risk_label": None,
               "rules": [], "error": r.get("error"), "findings_count": 0}

        if r.get("error"):
            total_errors += 1
            pkg_summaries.append(row)
            continue

        output = r.get("output") or {}
        scan_results = output.get("results", {})
        fired = [k for k, v in scan_results.items() if has_findings(v)]
        row["rules"] = fired
        row["findings_count"] = len(fired)
        for rule in fired:
            rule_counts[rule] += 1

        risk = output.get("risk_score")
        if risk:
            row["risk_score"] = risk.get("score")
            row["risk_label"] = risk.get("label")

        pkg_summaries.append(row)

    total = len(pkg_summaries)
    successful = total - total_errors
    flagged = sum(1 for p in pkg_summaries if p["findings_count"] > 0)

    # Score histogram (buckets of 1.0)
    score_buckets = defaultdict(int)
    score_buckets_eco = {eco: defaultdict(int) for eco in ecosystems}
    for p in pkg_summaries:
        if p["risk_score"] is not None:
            bucket = min(int(p["risk_score"]), 9)
            score_buckets[bucket] += 1
            score_buckets_eco[p["ecosystem"]][bucket] += 1

    # Risk label distribution
    risk_dist = defaultdict(int)
    eco_risk_dist = {eco: defaultdict(int) for eco in ecosystems}
    for p in pkg_summaries:
        if p["error"]:
            risk_dist["error"] += 1
            eco_risk_dist[p["ecosystem"]]["error"] += 1
        elif p["risk_label"]:
            label = p["risk_label"].lower()
            risk_dist[label] += 1
            eco_risk_dist[p["ecosystem"]][label] += 1
        else:
            risk_dist["none"] += 1
            eco_risk_dist[p["ecosystem"]]["none"] += 1

    # Per-ecosystem stats
    eco_stats = {}
    for eco in ecosystems:
        eco_pkgs = [p for p in pkg_summaries if p["ecosystem"] == eco]
        eco_stats[eco] = {
            "count": len(eco_pkgs),
            "flagged": sum(1 for p in eco_pkgs if p["findings_count"] > 0),
            "errors": sum(1 for p in eco_pkgs if p["error"]),
            "avg_score": 0,
        }
        scores = [p["risk_score"] for p in eco_pkgs if p["risk_score"] is not None]
        if scores:
            eco_stats[eco]["avg_score"] = sum(scores) / len(scores)

    # Top triggered rules
    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])

    html = build_report_html(
        total=total, successful=successful, flagged=flagged,
        total_errors=total_errors, gd_version=gd_version,
        ecosystems=ecosystems, eco_stats=eco_stats,
        score_buckets=dict(score_buckets),
        score_buckets_eco={k: dict(v) for k, v in score_buckets_eco.items()},
        risk_dist=dict(risk_dist),
        eco_risk_dist={k: dict(v) for k, v in eco_risk_dist.items()},
        top_rules=top_rules, pkg_summaries=pkg_summaries,
    )

    out_path = work_dir / "report.html"
    out_path.write_text(html)
    print(f"Report written to {out_path}")

    # Print summary to stdout
    print(f"\n{'='*60}")
    print(f"  Packages scanned: {total} ({successful} successful, {total_errors} errors)")
    print(f"  Packages flagged: {flagged}/{successful} ({flagged/successful*100:.1f}%)")
    scores = [p["risk_score"] for p in pkg_summaries if p["risk_score"] is not None]
    if scores:
        print(f"  Score: avg={sum(scores)/len(scores):.2f}  median={sorted(scores)[len(scores)//2]:.1f}  "
              f"max={max(scores):.1f}")
    for label in ["none", "low", "medium", "high", "critical"]:
        count = risk_dist.get(label, 0)
        pct = count / successful * 100 if successful else 0
        print(f"  {label:>10}: {count:4d} ({pct:5.1f}%)")
    print(f"{'='*60}")


def build_report_html(*, total, successful, flagged, total_errors, gd_version,
                      ecosystems, eco_stats, score_buckets, score_buckets_eco,
                      risk_dist, eco_risk_dist, top_rules, pkg_summaries):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scores = [p["risk_score"] for p in pkg_summaries if p["risk_score"] is not None]
    avg_score = sum(scores) / len(scores) if scores else 0
    median_score = sorted(scores)[len(scores) // 2] if scores else 0

    top_rule_name = escape(top_rules[0][0]) if top_rules else "-"
    top_rule_count = top_rules[0][1] if top_rules else 0
    top_rule_pct = f"{top_rule_count/successful*100:.1f}" if successful else "0"

    # Per-ecosystem histograms
    eco_hist = ""
    for eco in ecosystems:
        eco_hist += (f'<div><h3>{escape(eco.upper())}</h3>'
                     f'{templates.score_histogram(score_buckets_eco[eco], max_height=150, bar_width=32)}</div>\n')

    # Per-ecosystem risk bars
    eco_risk_html = ""
    for eco in ecosystems:
        eco_risk_html += f'<div><h3>{escape(eco.upper())}</h3>{templates.risk_label_bars(eco_risk_dist.get(eco, {}))}</div>\n'

    # Ecosystem table rows
    eco_rows = ""
    for eco in ecosystems:
        st = eco_stats[eco]
        eco_rows += (f'<tr><td>{escape(eco.upper())}</td><td>{st["count"]}</td>'
                     f'<td>{st["flagged"]}</td><td>{st["avg_score"]:.2f}</td>'
                     f'<td>{st["errors"]}</td></tr>\n')

    # Top rules table
    rules_html = ""
    for rule, count in top_rules[:30]:
        pct = (count / successful) * 100 if successful else 0
        bar_w = int(pct * 3)
        rules_html += (f'<tr><td>{escape(rule)}</td><td>{count}</td><td>'
                       f'<div style="display:flex;align-items:center;gap:8px">'
                       f'<div style="width:{bar_w}px;height:14px;background:#1976d2;border-radius:2px"></div>'
                       f'{pct:.1f}%</div></td></tr>\n')

    # Package table
    pkg_rows = ""
    for p in sorted(pkg_summaries, key=lambda x: -(x["risk_score"] or -1)):
        score_s = f'{p["risk_score"]:.1f}' if p["risk_score"] is not None else "-"
        label_s = p["risk_label"] or ("-" if not p["error"] else "err")
        rules = escape(", ".join(p["rules"])) if p["rules"] else "-"
        label_color = {"low": "#a5d6a7", "medium": "#fff176", "high": "#ffab91",
                       "critical": "#ef5350"}.get((p["risk_label"] or "").lower(), "")
        bg = f"background:{label_color}22" if label_color else ""
        pkg_rows += (f'<tr class="pkg-row" data-eco="{p["ecosystem"]}" '
                     f'data-label="{(p["risk_label"] or "none").lower()}" '
                     f'data-name="{escape(p["name"].lower())}" style="{bg}">'
                     f'<td>{escape(p["name"])}</td><td>{escape(p["ecosystem"].upper())}</td>'
                     f'<td>{score_s}</td><td>{label_s}</td>'
                     f'<td>{p["findings_count"]}</td>'
                     f'<td class="details">{rules}</td></tr>\n')

    body = f"""
<h1>GuardDog Benchmark Report</h1>
<p class="meta">Generated {ts} &mdash; {gd_version} &mdash; Top {total} packages</p>

<div class="cards">
  <div class="card"><div class="label">Packages</div><div class="value">{successful}</div>
    <div class="sub">{total_errors} errors</div></div>
  <div class="card"><div class="label">Flagged</div><div class="value">{flagged}</div>
    <div class="sub">{flagged/successful*100:.1f}% of scanned</div></div>
  <div class="card"><div class="label">Avg Score</div><div class="value">{avg_score:.1f}</div></div>
  <div class="card"><div class="label">Median Score</div><div class="value">{median_score:.1f}</div></div>
  <div class="card"><div class="label">Top Rule</div><div class="value" style="font-size:16px">{top_rule_name}</div>
    <div class="sub">{top_rule_count} packages ({top_rule_pct}%)</div></div>
</div>

<h2>Ecosystem Breakdown</h2>
<table>
<tr><th>Ecosystem</th><th>Packages</th><th>Flagged</th><th>Avg Score</th><th>Errors</th></tr>
{eco_rows}
</table>

<h2>Risk Score Distribution</h2>
<p style="color:#666;margin-bottom:8px">Distribution of risk scores (0-10). On legitimate packages, lower is better.</p>
<h3>All Ecosystems</h3>
{templates.score_histogram(score_buckets)}
<div class="two-col">{eco_hist}</div>

<h2>Risk Label Distribution</h2>
<div class="two-col">
<div><h3>All Ecosystems</h3>{templates.risk_label_bars(risk_dist)}</div>
<div style="display:flex;flex-direction:column;gap:16px">{eco_risk_html}</div>
</div>

<h2>Most Triggered Rules (Top 30)</h2>
<p style="color:#666;margin-bottom:8px">On legitimate packages, high trigger rates indicate potential noise.</p>
<table id="rulesTable">
<tr><th onclick="sortTable('rulesTable',0)">Rule</th>
<th onclick="sortTable('rulesTable',1)">Packages</th>
<th onclick="sortTable('rulesTable',2)">% of Total</th></tr>
{rules_html}
</table>

<h2>Per-Package Details</h2>
<div class="filters">
  <input type="text" id="pkgSearch" placeholder="Filter by package name..." oninput="filterPkgs()">
  <select id="ecoFilter" onchange="filterPkgs()">
    <option value="">All ecosystems</option>
    {templates.eco_filter_options(ecosystems)}
  </select>
  <select id="labelFilter" onchange="filterPkgs()">
    <option value="">All risk levels</option>
    <option value="none">None</option><option value="low">Low</option>
    <option value="medium">Medium</option><option value="high">High</option>
    <option value="critical">Critical</option>
  </select>
</div>
<table id="pkgTable">
<tr><th onclick="sortTable('pkgTable',0)">Package</th>
<th onclick="sortTable('pkgTable',1)">Ecosystem</th>
<th onclick="sortTable('pkgTable',2)">Score</th>
<th onclick="sortTable('pkgTable',3)">Label</th>
<th onclick="sortTable('pkgTable',4)">Rules Fired</th>
<th>Rules</th></tr>
{pkg_rows}
</table>"""

    return templates.render("GuardDog Benchmark Report", body)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    phase = args.phase

    if phase in ("all", "fetch"):
        run_fetch(work_dir, args.ecosystems, args.max_packages, args.force_fetch)
    if phase in ("all", "scan"):
        gd_bin = find_guarddog_bin(args.guarddog_bin)
        print(f"Using guarddog: {gd_bin}")
        run_scan(work_dir, args.ecosystems, gd_bin, args.workers, args.timeout)
    if phase in ("all", "report"):
        run_report(work_dir, args.ecosystems)


if __name__ == "__main__":
    main()
