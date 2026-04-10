# GuardDog Evaluation Suite

Three tools for measuring GuardDog quality:

- **run.py** -- Combined evaluation: precision, recall, F1 score, score distributions
- **benchmark.py** -- FP benchmark on top-N legitimate packages
- **recall.py** -- Recall benchmark on known-malicious packages

## Quick start

```bash
# Run the full combined evaluation (FP + recall + metrics)
uv run evals/run.py

# Customize
uv run evals/run.py --benign-packages 500 --workers 10 --threshold 5.0

# Change detection threshold and regenerate report (no re-scanning)
uv run evals/run.py --phase report --threshold 3.0

# Resample malicious packages from the dataset
uv run evals/run.py --regenerate-samples

# Run individual benchmarks
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

---

## recall.py -- Detection rate on malicious packages

Measures recall against a curated set of 500 known-malicious packages from [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset/).

Each package is extracted and scanned inside a [Nono](https://nono.sh) sandbox with no network access.

### Quick start

```bash
# Install nono-py (required for sandboxed scanning)
pip install nono-py

# Run the full recall benchmark
uv run evals/recall.py

# Smaller test
uv run evals/recall.py --ecosystems pypi --workers 3

# Only regenerate the report from cached results
uv run evals/recall.py --phase report

# Use a local clone of the malicious dataset (skip downloads)
uv run evals/recall.py --dataset-path /path/to/malicious-software-packages-dataset
```

### How it works

1. **Fetches** 500 malicious package ZIPs from GitHub (listed in `recall_samples.json`)
2. For each package, spawns a **sandboxed subprocess** (`recall_worker.py`) that:
   - Applies Nono sandbox (no network, restricted filesystem)
   - Extracts the encrypted ZIP (`password: infected`)
   - Runs guarddog source code analysis
   - Writes results and cleans up extracted files
3. **Generates** an HTML report with recall rates, false negatives, and per-package details

### Sample set

`recall_samples.json` contains a fixed, reproducible set of 500 packages:
- **250 PyPI** (246 malicious_intent + 4 compromised_lib)
- **250 NPM** (200 malicious_intent + 50 compromised_lib)

To regenerate from the latest dataset:
```bash
uv run evals/recall.py --regenerate-samples
```

### CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--work-dir` | `evals/workdir` | Working directory |
| `--phase` | `all` | Phases: `fetch`, `scan`, `report`, or `all` |
| `--ecosystems` | `pypi npm` | Which ecosystems |
| `--workers` | `5` | Parallel worker subprocesses |
| `--timeout` | `120` | Per-package timeout in seconds |
| `--dataset-path` | none | Local clone path (skip downloads) |
| `--no-sandbox` | off | Skip Nono sandbox (DANGEROUS) |
| `--regenerate-samples` | off | Regenerate `recall_samples.json` |

### Interpreting results

- **Recall rate**: % of malicious packages where at least one rule fired
- **False negatives**: packages that scored 0 (completely missed)
- **By category**: malicious_intent (purpose-built malware) vs compromised_lib (backdoored legit packages)
