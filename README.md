# GuardDog

[![Test](https://github.com/DataDog/guarddog/actions/workflows/checks.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/checks.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DataDog/guarddog/badge)](https://securityscorecards.dev/viewer/?uri=github.com/DataDog/guarddog)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12273/badge)](https://www.bestpractices.dev/projects/12273)

<p align="center">
  <img src="https://github.com/DataDog/guarddog/blob/main/docs/images/logo.png?raw=true" alt="GuardDog" width="300" />
</p>

GuardDog is a CLI tool that identifies malicious PyPI and npm packages, Go modules, GitHub actions, or VSCode extensions. It runs static analysis on package source code (through Semgrep and YARA rules) and analyzes package metadata to detect supply chain attacks.

**What makes GuardDog different:** Instead of just listing suspicious patterns, GuardDog correlates findings to identify actual **risks** based on attack chains. A package needs both the **capability** to perform an action (e.g., network access) and a **threat indicator** (e.g., suspicious domain) in the same file to be flagged as high risk.

It downloads and scans code from:

* NPM: Packages hosted in [npmjs.org](https://www.npmjs.com/)
* PyPI: Source files (tar.gz) packages hosted in [PyPI.org](https://pypi.org/)
* Go: GoLang source files of repositories hosted in [GitHub.com](https://github.com)
* RubyGems: Gem packages hosted in [rubygems.org](https://rubygems.org/)
* GitHub Actions: Javascript source files of repositories hosted in [GitHub.com](https://github.com)
* VSCode Extensions: Extensions (.vsix) packages hosted in [marketplace.visualstudio.com](https://marketplace.visualstudio.com/)

![GuardDog demo usage](https://github.com/DataDog/guarddog/blob/main/docs/images/demo.png?raw=true)

## How GuardDog Works

GuardDog uses a **risk-based detection model** that correlates code capabilities with threat indicators:

1. **Detection**: Rules identify either **capabilities** (what code *can* do) or **threats** (suspicious indicators)
2. **Correlation**: Capabilities and threats found in the same file form **risks**
3. **Scoring**: Risks are scored (0-10) based on attack chain completeness and sophistication
4. **Reporting**: Packages receive a severity rating (low/medium/high) with detailed risk breakdown

### Why This Approach?

Traditional SAST tools flag every suspicious pattern independently, leading to alert fatigue. GuardDog understands that:

- **Capability alone** isn't malicious (network libraries should make HTTP requests)
- **Threat indicators alone** might be false positives (test fixtures, documentation)
- **Capability + Threat together** indicates actual risk (code that can *and will* do something malicious)

### Risk Scoring

Packages receive a score from **0-10** based on four factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Severity** | 25% | Highest severity finding (low/medium/high) |
| **Attack Chain** | 30% | Presence of complete attack stages (early → mid/late) |
| **Specificity** | 25% | How specific patterns are (vs generic/common code) |
| **Sophistication** | 20% | Use of evasion techniques (obfuscation, anti-debugging) |

**Score Labels:**
- **0**: No risks detected
- **1-3**: Low risk (single-stage threats, low specificity)
- **3.1-7.5**: Medium risk (partial attack chain, metadata indicators, or single-stage code findings)
- **7.6-10**: High risk (multi-stage attack chain with source code evidence — near-certainty of compromise)

**Attack Chain Stages** (based on MITRE ATT&CK):
- **Early**: Initial access, execution capabilities
- **Mid**: Persistence, defense evasion, credential access
- **Late**: Command & control, exfiltration, impact
---
### Check out the new Datadog Agent [integration](https://docs.datadoghq.com/integrations/guarddog/) and Cloud SIEM [content pack](https://app.datadoghq.com/security/siem/content-packs?query=guarddog) for GuardDog.
---

## Getting started

### Installation

The easiest way to run GuardDog is to use [`uvx`](https://docs.astral.sh/uv/guides/tools/):

```sh
uvx guarddog pypi scan requests
```

To install it locally:

```sh
uv tool install guarddog
# or
pip install guarddog
```

Or use the Docker image:

```sh
docker pull ghcr.io/datadog/guarddog
alias guarddog='docker run --rm ghcr.io/datadog/guarddog'
```

*Note: On Windows, the only supported installation method is Docker.*

### Sample usage

```sh
# Scan the most recent version of the 'requests' package
guarddog pypi scan requests

# Scan a specific version of the 'requests' package
guarddog pypi scan requests --version 2.28.1

# Scan the 'request' package using 2 specific heuristics
guarddog pypi scan requests --rules exec-base64 --rules code-execution

# Scan the 'requests' package using all rules but one
guarddog pypi scan requests --exclude-rules exec-base64

# Scan a local package archive
guarddog pypi scan /tmp/triage.tar.gz

# Scan a local package directory
guarddog pypi scan /tmp/triage/

# Scan every package referenced in a requirements.txt file of a local folder
guarddog pypi verify workspace/guarddog/requirements.txt

# Scan every package referenced in a requirements.txt file and output a sarif file - works only for verify
guarddog pypi verify --output-format=sarif workspace/guarddog/requirements.txt

# Output JSON to standard output - works for every command
guarddog pypi scan requests --output-format=json

# All the commands also work on npm, go, rubygems
guarddog npm scan express

guarddog go scan github.com/DataDog/dd-trace-go

guarddog go verify /tmp/repo/go.mod

# Scan RubyGems packages
guarddog rubygems scan rails

guarddog rubygems verify /tmp/repo/Gemfile.lock

# Additionally can support scanning GitHub actions that are implemented in JavaScript
guarddog github_action scan DataDog/synthetics-ci-github-action

guarddog github_action verify /tmp/repo/.github/workflows/main.yml

# Scan VSCode extensions from the marketplace
guarddog extension scan ms-python.python

# Scan a specific version of a VSCode extension
guarddog extension scan ms-python.python --version 2023.20.0

# Scan a local VSCode extension directory or VSIX archive
guarddog extension scan /tmp/my-extension/

# Run in debug mode
guarddog --log-level debug npm scan express
```


## Sandboxed Scanning

When scanning packages, GuardDog runs source code analysis inside a **kernel-level sandbox** (Linux via Landlock, macOS via Seatbelt, using [nono](https://github.com/always-further/nono-py)). The sandbox blocks all network access and restricts filesystem operations to only the paths needed for analysis. This protects against malicious packages that attempt to execute code during archive extraction or scanning.

The sandbox is enabled by default on supported platforms:

```sh
# Sandboxed by default
guarddog pypi scan requests

# Explicitly disable the sandbox
guarddog pypi scan requests --no-sandbox
```

For remote packages, extraction happens in an isolated subprocess with its own sandbox, so that malicious archives cannot tamper with files before they are scanned.

The sandbox was introduced to mitigate path traversal and code execution vulnerabilities during archive extraction (CVE-2022-23530, CVE-2022-23531, CVE-2026-22870, CVE-2026-22871).

## Rules

GuardDog uses two types of detection rules, both participating in the risk-based scoring engine:

* **Source code rules** (YARA/Semgrep): Static analysis of package source code detecting capabilities and threats
* **Metadata rules** (Python detectors): Analysis of package registry metadata detecting supply chain attack indicators

For the full list of rules per ecosystem, see **[RULES.md](RULES.md)**.

For guidance on writing new rules, see **[WRITING_RULES.md](WRITING_RULES.md)**.

## Running GuardDog in a GitHub Action

The easiest way to integrate GuardDog in your CI pipeline is to leverage the SARIF output format, and upload it to GitHub's [code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) feature.

Using this, you get:
* Automated comments to your pull requests based on the GuardDog scan output
* Built-in false positive management directly in the GitHub UI


Sample GitHub Action using GuardDog:

```yaml
name: GuardDog

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

permissions:
  contents: read

jobs:
  guarddog:
    permissions:
      contents: read # for actions/checkout to fetch code
      security-events: write # for github/codeql-action/upload-sarif to upload SARIF results
    name: Scan dependencies
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v7

      - run: uvx guarddog pypi verify requirements.txt --output-format sarif --exclude-rules repository_integrity_mismatch > guarddog.sarif

      - name: Upload SARIF file to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          category: guarddog-builtin
          sarif_file: guarddog.sarif
```


## Development

### Running a local version of GuardDog

* Ensure poetry has an env with `python >=3.10` `poetry env use 3.10.0`
* Install dependencies `poetry install`
* Run guarddog `poetry run guarddog` or `poetry shell` then run `guarddog`

### Unit tests

Running all unit tests: `make test`

Running unit tests against Semgrep rules: `make test-semgrep-rules` (tests are [here](https://github.com/DataDog/guarddog/tree/main/tests/analyzer/sourcecode)). These use the standard methodology for [testing Semgrep rules](https://semgrep.dev/docs/writing-rules/testing-rules/).

Running unit tests against package metadata heuristics: `make test-metadata-rules` (tests are [here](https://github.com/DataDog/guarddog/tree/main/tests/analyzer/metadata)).

### Benchmarking

You can run GuardDog on legitimate and malicious packages to determine false positives and false negatives. See [./tests/samples](./tests/samples)

### Code quality checks

Run the type checker with
```shell
mypy --install-types --non-interactive guarddog
```
and the linter with
```shell
flake8 guarddog --count --select=E9,F63,F7,F82 --show-source --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data
flake8 guarddog --count --max-line-length=120 --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data --ignore=E203,W503
```

### Configuration via Environment Variables

GuardDog's behavior can be customized using environment variables:

#### General Configuration

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `GUARDDOG_PARALLELISM` | Number of threads to use for parallel processing | Number of CPUs available |
| `GUARDDOG_VERIFY_EXHAUSTIVE_DEPENDENCIES` | Analyze all possible versions of dependencies (`true`/`false`) | `false` |
| `GUARDDOG_TOP_PACKAGES_CACHE_LOCATION` | Location of the top packages cache directory | `guarddog/analyzer/metadata/resources` |
| `GUARDDOG_YARA_EXT_EXCLUDE` | Comma-separated list of file extensions to exclude from YARA scanning | `ini,md,rst,txt,lock,json,yaml,yml,toml,xml,html,csv,sql,pdf,doc,docx,ppt,pptx,xls,xlsx,odt,changelog,readme,makefile,dockerfile,pkg-info,d.ts` |

#### Semgrep Configuration

GuardDog uses `Semgrep`, a powerful static analysis tool that scans code for patterns. 

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `GUARDDOG_SEMGREP_MAX_TARGET_BYTES` | Maximum size of a file that Semgrep will analyze (files exceeding this will be skipped) | 10MB (10485760 bytes) |
| `GUARDDOG_SEMGREP_TIMEOUT` | Maximum time in seconds that Semgrep will spend running a rule on a single file | 10 seconds |

#### Archive Extraction Security Limits

GuardDog implements multiple security checks when extracting package archives to protect against compression bombs and file descriptor exhaustion attacks:

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `GUARDDOG_MAX_UNCOMPRESSED_SIZE` | Maximum allowed uncompressed size in bytes (prevents disk space exhaustion) | 2147483648 (2 GB) |
| `GUARDDOG_MAX_COMPRESSION_RATIO` | Maximum allowed compression ratio (detects suspicious compression patterns) | 100 (100:1) |
| `GUARDDOG_MAX_FILE_COUNT` | Maximum number of files allowed in an archive (prevents file descriptor/inode exhaustion) | 100000 |

## Maintainers

* [Sebastian Obregoso](https://www.linkedin.com/in/sebastianobregoso/)
* [Ian Kretz](https://github.com/ikretz)
* [Tesnim Hamdouni](https://github.com/tesnim5hamdouni)

## Authors
* [Ellen Wang](https://www.linkedin.com/in/ellen-wang-4bb5961a0/)
* [Christophe Tafani-Dereeper](https://github.com/christophetd)

## Acknowledgments

Inspiration:
* [Backstabber’s Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://arxiv.org/pdf/2005.09535)
* [What are Weak Links in the npm Supply Chain?](https://arxiv.org/pdf/2112.10165.pdf)
* [A Survey on Common Threats in npm and PyPi Registries](https://arxiv.org/pdf/2108.09576.pdf)
* [A Benchmark Comparison of Python Malware Detection Approaches](https://arxiv.org/pdf/2209.13288.pdf)
* [Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages](https://arxiv.org/pdf/2002.01139)
