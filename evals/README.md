# GuardDog Evaluation Suite

Three tools for measuring GuardDog quality:

- **run.py** -- Combined evaluation: precision, recall, F1 score, score distributions
- **benchmark.py** -- FP benchmark on top-N legitimate packages
- **recall.py** -- Recall benchmark on known-malicious packages

> **Safety:** Malicious packages are extracted and scanned inside a [Nono](https://nono.sh) kernel-level sandbox with no network access and restricted filesystem. `nono-py` is installed automatically by `uv`. Pass `--no-sandbox` to skip (not recommended).

## Quick start

```bash
# Run the full combined evaluation (FP + recall + metrics)
uv run evals/run.py

# Customize
uv run evals/run.py --benign-packages 500 --workers 10 --threshold 5.0

# Change detection threshold and regenerate report (no re-scanning)
uv run evals/run.py --phase report --threshold 3.0

# Resample malicious packages from the dataset
uv run evals/run.py --regenerate-samples --samples-per-ecosystem 500
```

## What it does

### False positive measurement (benchmark.py)
1. **Fetches** the top N most-popular packages from PyPI and NPM
2. **Scans** each package with the locally-installed `guarddog`
3. **Generates** a report with score distributions, rule trigger rates, and per-package details

Since these are well-known legitimate packages, any findings are noise.

### Recall measurement (recall.py)
1. **Downloads** known-malicious package ZIPs from [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset/)
2. **Extracts and scans** each package inside a [Nono](https://nono.sh) sandbox (no network, restricted filesystem)
3. **Generates** a report with recall rates, score distributions, false negatives, and per-package details

Prioritizes compromised_lib packages (supply chain attacks) which are rare and high-value.

### Combined evaluation (run.py)
1. **Runs both** benchmarks above
2. **Computes** precision, recall, and F1 score at a configurable detection threshold
3. **Generates** a combined report with confusion matrix, overlaid score histograms, score statistics, and a threshold sweep table

## run.py CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--work-dir` | `evals/workdir` | Working directory for all data/results/reports |
| `--phase` | `all` | `all` runs both benchmarks + report; `report` regenerates from cached results |
| `--ecosystems` | `pypi npm` | Ecosystems to evaluate |
| `--benign-packages` | `1000` | Top N legitimate packages per ecosystem |
| `--workers` | `10` | Parallel scan threads |
| `--threshold` | `5.0` | Risk score threshold for "detected" classification |
| `--timeout` | `300` | Per-package scan timeout in seconds |
| `--no-sandbox` | off | Skip Nono sandbox for recall (DANGEROUS) |
| `--regenerate-samples` | off | Resample malicious packages from the dataset |
| `--samples-per-ecosystem` | `250` | Total malicious samples per ecosystem (compromised_lib first, then malicious_intent) |
| `--seed` | random | Hex seed for sampling reproducibility (printed on generation) |

## Output

Results are saved to `evals/workdir/` (gitignored):
- `data/` -- cached package lists
- `results/` -- individual FP scan results (resumable)
- `recall_results/` -- individual recall scan results (resumable)
- `malicious_zips/` -- cached malicious package downloads
- `report.html` -- FP benchmark report
- `recall_report.html` -- recall benchmark report
- `combined_report.html` -- combined precision/recall/F1 report

## Sample set

`recall_samples.json` contains a curated set of malicious packages pinned to a dataset commit SHA. When regenerating:

- **compromised_lib** packages (supply chain attacks) are always prioritized, filling up to half the per-ecosystem budget
- **malicious_intent** packages fill the rest, randomly sampled
- A cryptographic seed is generated and stored for reproducibility
- Pass `--seed <hex>` to reproduce a specific sample

```bash
# Resample with 500 packages per ecosystem
uv run evals/run.py --regenerate-samples --samples-per-ecosystem 500

# Reproduce a previous sample
uv run evals/run.py --regenerate-samples --seed a1b2c3d4e5f6a7b8
```

---

## Running individual benchmarks

### benchmark.py -- FP benchmark

```bash
uv run evals/benchmark.py
uv run evals/benchmark.py --max-packages 50 --ecosystems pypi
uv run evals/benchmark.py --phase report
```

| Flag | Default | Description |
|------|---------|-------------|
| `--max-packages` | `1000` | Top N packages per ecosystem |
| `--workers` | `20` | Parallel scan threads |
| `--guarddog-bin` | auto-detected | Path to guarddog binary |
| `--force-fetch` | off | Re-fetch package lists even if cached |

### recall.py -- Recall benchmark

```bash
# Requires nono-py: pip install nono-py
uv run evals/recall.py
uv run evals/recall.py --ecosystems pypi --workers 3
uv run evals/recall.py --dataset-path /path/to/local/clone
uv run evals/recall.py --regenerate-samples --samples-per-ecosystem 100
```

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `5` | Parallel worker subprocesses |
| `--timeout` | `120` | Per-package timeout in seconds |
| `--dataset-path` | none | Local clone of the malicious dataset (skip downloads) |
| `--no-sandbox` | off | Skip Nono sandbox (DANGEROUS) |
| `--samples-per-ecosystem` | `250` | Total samples per ecosystem when regenerating |

## Interpreting results

- **Score distribution (FP)**: on legitimate packages, most should score 0-3. Rules firing on >10% of packages are too noisy.
- **Score distribution (recall)**: on malicious packages, scores should skew high. Low-scoring malicious packages are false negatives.
- **Threshold sweep**: the combined report shows precision/recall/F1 at every integer threshold, helping pick the right operating point.
- **By category**: compromised_lib (backdoored real packages) are harder to detect than malicious_intent (purpose-built malware). Track both separately.
