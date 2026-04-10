#!/usr/bin/env python3
"""
GuardDog Combined Evaluation

Runs both the FP benchmark (precision) and malicious recall benchmark,
then computes combined metrics: precision, recall, F1, and score distributions.

Usage:
    uv run evals/run.py
    uv run evals/run.py --benign-packages 100 --workers 10
    uv run evals/run.py --threshold 5.0
    uv run evals/run.py --phase report --threshold 3.0
    uv run evals/run.py --regenerate-samples
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path


EVALS_DIR = Path(__file__).parent
DEFAULT_WORK_DIR = EVALS_DIR / "workdir"


def parse_args():
    p = argparse.ArgumentParser(description="GuardDog Combined Evaluation")
    p.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    p.add_argument("--phase", choices=["all", "report"], default="all",
                   help="'all' runs both benchmarks then report; 'report' regenerates from cached results")
    p.add_argument("--ecosystems", nargs="+", choices=["pypi", "npm"], default=["pypi", "npm"])
    p.add_argument("--benign-packages", type=int, default=1000,
                   help="Number of top legitimate packages per ecosystem for FP benchmark")
    p.add_argument("--workers", type=int, default=10,
                   help="Parallel workers for scanning")
    p.add_argument("--threshold", type=float, default=5.0,
                   help="Risk score threshold for 'detected' classification (score >= threshold)")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--dataset-path", type=Path, default=None,
                   help="Local clone of malicious-software-packages-dataset")
    p.add_argument("--no-sandbox", action="store_true")
    p.add_argument("--regenerate-samples", action="store_true")
    return p.parse_args()


def run_subprocess(cmd: list[str], label: str):
    print(f"\n{'='*60}")
    print(f"  Running: {label}")
    print(f"  Command: {' '.join(cmd)}")
    print(f"{'='*60}\n")
    result = subprocess.run(cmd, cwd=str(EVALS_DIR.parent))
    if result.returncode != 0:
        print(f"WARNING: {label} exited with code {result.returncode}")


def load_benign_results(work_dir: Path, ecosystems: list[str]) -> list[dict]:
    results = []
    results_dir = work_dir / "results"
    for eco in ecosystems:
        d = results_dir / eco
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix == ".json":
                data = json.loads(f.read_text())
                data["_source"] = "benign"
                results.append(data)
    return results


def load_malicious_results(work_dir: Path, ecosystems: list[str]) -> list[dict]:
    results = []
    results_dir = work_dir / "recall_results"
    for eco in ecosystems:
        d = results_dir / eco
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix == ".json":
                data = json.loads(f.read_text())
                data["_source"] = "malicious"
                results.append(data)
    return results


def extract_score(result: dict) -> float | None:
    """Extract the risk score from a result dict (handles both benchmark and recall formats)."""
    if result.get("error"):
        return None

    # benchmark.py format: output.risk_score.score
    output = result.get("output") or result.get("scan_output") or {}
    risk = output.get("risk_score")
    if isinstance(risk, dict):
        return risk.get("score")

    return None


def generate_combined_report(work_dir: Path, ecosystems: list[str], threshold: float):
    print("Loading results...")
    benign = load_benign_results(work_dir, ecosystems)
    malicious = load_malicious_results(work_dir, ecosystems)

    if not benign:
        print("WARNING: No benign results found. Run benchmark.py first.")
    if not malicious:
        print("WARNING: No malicious results found. Run recall.py first.")

    benign_ok = [r for r in benign if not r.get("error")]
    malicious_ok = [r for r in malicious if not r.get("error")]

    benign_scores = [s for s in (extract_score(r) for r in benign_ok) if s is not None]
    malicious_scores = [s for s in (extract_score(r) for r in malicious_ok) if s is not None]

    # Classification at threshold
    tp = sum(1 for s in malicious_scores if s >= threshold)  # malicious correctly flagged
    fn = sum(1 for s in malicious_scores if s < threshold)   # malicious missed
    fp = sum(1 for s in benign_scores if s >= threshold)     # benign incorrectly flagged
    tn = sum(1 for s in benign_scores if s < threshold)      # benign correctly clean

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Score stats
    def stats(scores):
        if not scores:
            return {"avg": 0, "median": 0, "p25": 0, "p75": 0, "max": 0, "min": 0, "count": 0}
        s = sorted(scores)
        n = len(s)
        return {
            "avg": sum(s) / n, "median": s[n // 2],
            "p25": s[n // 4], "p75": s[3 * n // 4],
            "max": s[-1], "min": s[0], "count": n,
        }

    benign_stats = stats(benign_scores)
    malicious_stats = stats(malicious_scores)

    # Score buckets for histogram overlay
    benign_buckets = defaultdict(int)
    malicious_buckets = defaultdict(int)
    for s in benign_scores:
        benign_buckets[min(int(s), 9)] += 1
    for s in malicious_scores:
        malicious_buckets[min(int(s), 9)] += 1

    # Threshold sweep for ROC-like table
    threshold_sweep = []
    for t in [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]:
        _tp = sum(1 for s in malicious_scores if s >= t)
        _fp = sum(1 for s in benign_scores if s >= t)
        _recall = _tp / len(malicious_scores) * 100 if malicious_scores else 0
        _fpr = _fp / len(benign_scores) * 100 if benign_scores else 0
        _prec = _tp / (_tp + _fp) * 100 if (_tp + _fp) > 0 else 0
        _f1 = 2 * _prec * _recall / (_prec + _recall) if (_prec + _recall) > 0 else 0
        threshold_sweep.append({"t": t, "tp": _tp, "fp": _fp, "recall": _recall,
                                "fpr": _fpr, "precision": _prec, "f1": _f1})

    html = build_combined_html(
        threshold=threshold, tp=tp, fn=fn, fp=fp, tn=tn,
        precision=precision, recall=recall, f1=f1,
        benign_stats=benign_stats, malicious_stats=malicious_stats,
        benign_buckets=dict(benign_buckets), malicious_buckets=dict(malicious_buckets),
        threshold_sweep=threshold_sweep,
        n_benign=len(benign_ok), n_malicious=len(malicious_ok),
    )

    out_path = work_dir / "combined_report.html"
    out_path.write_text(html)
    print(f"Report written to {out_path}")

    print(f"\n{'='*60}")
    print(f"  Combined Results (threshold: score >= {threshold})")
    print(f"  Benign: {len(benign_ok)} packages | Malicious: {len(malicious_ok)} packages")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision: {precision:.1%}  Recall: {recall:.1%}  F1: {f1:.1%}")
    print(f"  Benign scores:    avg={benign_stats['avg']:.2f}  median={benign_stats['median']:.1f}")
    print(f"  Malicious scores: avg={malicious_stats['avg']:.2f}  median={malicious_stats['median']:.1f}")
    print(f"{'='*60}")


def build_combined_html(*, threshold, tp, fn, fp, tn, precision, recall, f1,
                        benign_stats, malicious_stats,
                        benign_buckets, malicious_buckets,
                        threshold_sweep, n_benign, n_malicious):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Confusion matrix
    cm_html = f"""<table style="width:auto;margin:16px 0">
    <tr><th></th><th>Predicted Malicious<br>(score >= {threshold})</th><th>Predicted Benign<br>(score &lt; {threshold})</th></tr>
    <tr><td><b>Actually Malicious</b></td><td style="background:#c8e6c9"><b>TP = {tp}</b></td><td style="background:#ffcdd2"><b>FN = {fn}</b></td></tr>
    <tr><td><b>Actually Benign</b></td><td style="background:#ffcdd2"><b>FP = {fp}</b></td><td style="background:#c8e6c9"><b>TN = {tn}</b></td></tr>
    </table>"""

    # Overlaid histogram
    all_buckets = set(benign_buckets.keys()) | set(malicious_buckets.keys())
    max_count = max(max(benign_buckets.values(), default=1), max(malicious_buckets.values(), default=1))
    hist_bars = ""
    for b in range(10):
        bc = benign_buckets.get(b, 0)
        mc = malicious_buckets.get(b, 0)
        bh = int((bc / max_count) * 180) if max_count else 0
        mh = int((mc / max_count) * 180) if max_count else 0
        label = f"{b}-{b+1}" if b < 9 else "9-10"
        is_threshold = b >= int(threshold)
        border = "border-left:2px solid #d32f2f" if b == int(threshold) else ""
        hist_bars += (f'<div style="display:flex;flex-direction:column;align-items:center;gap:2px;{border};padding-left:4px">'
                      f'<div style="display:flex;gap:2px;align-items:flex-end;height:180px">'
                      f'<div style="width:18px;height:{bh}px;background:#90caf9;border-radius:2px 2px 0 0" title="Benign: {bc}"></div>'
                      f'<div style="width:18px;height:{mh}px;background:#ef9a9a;border-radius:2px 2px 0 0" title="Malicious: {mc}"></div>'
                      f'</div>'
                      f'<span style="font-size:10px;color:#666">{label}</span></div>\n')

    # Threshold sweep table
    sweep_rows = ""
    for row in threshold_sweep:
        is_current = abs(row["t"] - threshold) < 0.5
        bg = "background:#e3f2fd" if is_current else ""
        sweep_rows += (f'<tr style="{bg}"><td>{row["t"]:.0f}</td>'
                       f'<td>{row["recall"]:.1f}%</td><td>{row["fpr"]:.1f}%</td>'
                       f'<td>{row["precision"]:.1f}%</td><td>{row["f1"]:.1f}%</td>'
                       f'<td>{row["tp"]}</td><td>{row["fp"]}</td></tr>\n')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GuardDog Combined Evaluation</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         max-width: 1200px; margin: 0 auto; padding: 20px; background: #fafafa; color: #222; }}
  h1 {{ margin-bottom: 8px; }}
  h2 {{ margin: 32px 0 12px; border-bottom: 2px solid #1976d2; padding-bottom: 4px; }}
  .meta {{ color: #666; margin-bottom: 24px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px; margin: 16px 0; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card .label {{ font-size: 13px; color: #666; }}
  .card .value {{ font-size: 28px; font-weight: 700; }}
  .card .sub {{ font-size: 12px; color: #999; margin-top: 2px; }}
  .green {{ color: #2e7d32; }}
  .red {{ color: #c62828; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; background: #fff;
           box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 14px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
  th {{ background: #1976d2; color: #fff; }}
  .note {{ background: #e3f2fd; border-radius: 8px; padding: 16px; margin: 16px 0; font-size: 14px; }}
  .legend {{ display: flex; gap: 16px; margin: 8px 0; font-size: 13px; }}
  .legend span {{ display: inline-flex; align-items: center; gap: 4px; }}
  .legend-box {{ width: 14px; height: 14px; border-radius: 2px; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
</style>
</head>
<body>

<h1>GuardDog Combined Evaluation</h1>
<p class="meta">Generated {ts} &mdash; Detection threshold: score >= {threshold}</p>

<div class="note">
  <b>Definition:</b> A package is classified as "detected" (malicious) if its GuardDog risk score is <b>>= {threshold}</b>.
  Adjust with <code>--threshold</code>. See the threshold sweep table below for other values.
  <br><br>
  <b>Detailed reports:</b>
  <a href="report.html">FP Benchmark (benign packages)</a> |
  <a href="recall_report.html">Recall Benchmark (malicious packages)</a>
</div>

<div class="cards">
  <div class="card"><div class="label">Precision</div><div class="value {'green' if precision > 0.8 else 'red'}">{precision:.1%}</div>
    <div class="sub">TP / (TP + FP)</div></div>
  <div class="card"><div class="label">Recall</div><div class="value {'green' if recall > 0.8 else 'red'}">{recall:.1%}</div>
    <div class="sub">TP / (TP + FN)</div></div>
  <div class="card"><div class="label">F1 Score</div><div class="value {'green' if f1 > 0.8 else 'red'}">{f1:.1%}</div>
    <div class="sub">harmonic mean</div></div>
  <div class="card"><div class="label">Benign Packages</div><div class="value">{n_benign}</div></div>
  <div class="card"><div class="label">Malicious Packages</div><div class="value">{n_malicious}</div></div>
</div>

<h2>Confusion Matrix</h2>
{cm_html}

<h2>Score Distribution: Benign vs Malicious</h2>
<p style="color:#666;margin-bottom:8px">Overlaid histograms. The red line marks the detection threshold ({threshold}). Good separation = less overlap.</p>
<div class="legend">
  <span><div class="legend-box" style="background:#90caf9"></div> Benign ({n_benign})</span>
  <span><div class="legend-box" style="background:#ef9a9a"></div> Malicious ({n_malicious})</span>
  <span style="color:#d32f2f">| Threshold = {threshold}</span>
</div>
<div style="display:flex;gap:2px;align-items:flex-end;padding:12px 0">
{hist_bars}
</div>

<h2>Score Statistics</h2>
<table style="width:auto">
<tr><th></th><th>Count</th><th>Avg</th><th>Median</th><th>P25</th><th>P75</th><th>Min</th><th>Max</th></tr>
<tr><td><b>Benign</b></td><td>{benign_stats['count']}</td>
    <td>{benign_stats['avg']:.2f}</td><td>{benign_stats['median']:.1f}</td>
    <td>{benign_stats['p25']:.1f}</td><td>{benign_stats['p75']:.1f}</td>
    <td>{benign_stats['min']:.1f}</td><td>{benign_stats['max']:.1f}</td></tr>
<tr><td><b>Malicious</b></td><td>{malicious_stats['count']}</td>
    <td>{malicious_stats['avg']:.2f}</td><td>{malicious_stats['median']:.1f}</td>
    <td>{malicious_stats['p25']:.1f}</td><td>{malicious_stats['p75']:.1f}</td>
    <td>{malicious_stats['min']:.1f}</td><td>{malicious_stats['max']:.1f}</td></tr>
</table>

<h2>Threshold Sweep</h2>
<p style="color:#666;margin-bottom:8px">How metrics change at different thresholds. Highlighted row = current threshold ({threshold}).</p>
<table style="width:auto">
<tr><th>Threshold</th><th>Recall</th><th>FPR</th><th>Precision</th><th>F1</th><th>TP</th><th>FP</th></tr>
{sweep_rows}
</table>

</body>
</html>"""


def main():
    args = parse_args()
    work_dir = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    if args.regenerate_samples:
        subprocess.run([sys.executable, str(EVALS_DIR / "recall.py"), "--regenerate-samples"],
                       cwd=str(EVALS_DIR.parent))
        return

    if args.phase == "all":
        eco_args = []
        for eco in args.ecosystems:
            eco_args.extend(["--ecosystems", eco])

        # Run FP benchmark
        run_subprocess([
            sys.executable, str(EVALS_DIR / "benchmark.py"),
            "--work-dir", str(work_dir),
            "--max-packages", str(args.benign_packages),
            "--workers", str(args.workers),
            "--timeout", str(args.timeout),
            *eco_args,
        ], "FP Benchmark (benign packages)")

        # Run recall benchmark
        recall_cmd = [
            sys.executable, str(EVALS_DIR / "recall.py"),
            "--work-dir", str(work_dir),
            "--workers", str(min(args.workers, 5)),
            "--timeout", str(args.timeout),
            *eco_args,
        ]
        if args.dataset_path:
            recall_cmd.extend(["--dataset-path", str(args.dataset_path)])
        if args.no_sandbox:
            recall_cmd.append("--no-sandbox")
        run_subprocess(recall_cmd, "Recall Benchmark (malicious packages)")

    generate_combined_report(work_dir, args.ecosystems, args.threshold)


if __name__ == "__main__":
    main()
