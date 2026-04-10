# GuardDog Evaluation Suite

Benchmark GuardDog against the top most-popular PyPI and NPM packages to measure false positive rates and score distributions.

## Quick start

```bash
# From the repo root, run the full benchmark (top 1000 PyPI + NPM, 20 workers)
uv run evals/benchmark.py

# Smaller test run
uv run evals/benchmark.py --max-packages 50 --ecosystems pypi

# Only regenerate the report from existing results
uv run evals/benchmark.py --phase report

# Resume an interrupted scan (already-scanned packages are skipped)
uv run evals/benchmark.py --phase scan
```

## What it does

1. **Fetches** the top N most-popular packages from PyPI and NPM
2. **Scans** each package with the locally-installed `guarddog`
3. **Generates** a self-contained HTML report with:
   - Risk score distribution (histogram + per-ecosystem breakdown)
   - Risk label distribution (none / low / medium / high / critical)
   - Most-triggered rules (noise indicators)
   - Per-package searchable/filterable detail table

## CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--work-dir` | `evals/workdir` | Working directory for data, results, and report |
| `--phase` | `all` | Run specific phase: `fetch`, `scan`, `report`, or `all` |
| `--ecosystems` | `pypi npm` | Ecosystems to benchmark |
| `--max-packages` | `1000` | Number of top packages per ecosystem |
| `--workers` | `20` | Parallel scan threads |
| `--timeout` | `300` | Per-package scan timeout in seconds |
| `--force-fetch` | off | Re-fetch package lists even if cached |
| `--guarddog-bin` | auto-detected | Path to guarddog binary (defaults to `guarddog` on PATH) |

## Output

Results are saved to `evals/workdir/` (gitignored):
- `data/pypi_packages.json` / `data/npm_packages.json` — cached package lists
- `results/{ecosystem}/{package}.json` — individual scan results (resumable)
- `report.html` — the benchmark report

## Interpreting results

Since these are well-known legitimate packages, any findings are likely false positives.
A good rule should have a low trigger rate on this dataset. Key metrics:

- **Score distribution**: most packages should score 0-3 (low/none)
- **Rule trigger rate**: rules firing on >10% of packages likely have pattern issues
- **Per-package detail**: inspect high-scoring packages to understand what triggered
