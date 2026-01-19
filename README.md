# GuardDog

[![Test](https://github.com/DataDog/guarddog/actions/workflows/checks.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/checks.yml)

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
- **4-6**: Medium risk (partial attack chain or sophisticated single stage)
- **7-10**: High risk (complete attack chain with high specificity)

**Attack Chain Stages** (based on MITRE ATT&CK):
- **Early**: Initial access, execution capabilities
- **Mid**: Persistence, defense evasion, credential access
- **Late**: Command & control, exfiltration, impact

## Getting started

### Installation

```sh
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


## Heuristics

GuardDog comes with 2 types of heuristics:

* [**Source code heuristics**](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/sourcecode): Semgrep rules running against the package source code.

* [**Package metadata heuristics**](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/metadata): Python or Javascript heuristics running against the package metadata on PyPI or npm.

<!-- BEGIN_RULE_LIST -->
### PyPI

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| api-obfuscation | Identify obfuscated API calls using alternative Python syntax patterns |
| shady-links | Identify when a package contains an URL to a domain with a suspicious extension |
| obfuscation | Identify when a package uses a common obfuscation method often used by malware |
| clipboard-access | Identify when a package reads or write data from the clipboard |
| exfiltrate-sensitive-data | Identify when a package reads and exfiltrates sensitive data from the local system |
| download-executable | Identify when a package downloads and makes executable a remote binary |
| exec-base64 | Identify when a package dynamically executes base64-encoded code |
| silent-process-execution | Identify when a package silently executes an executable |
| dll-hijacking | Identifies when a malicious package manipulates a trusted application into loading a malicious DLL |
| steganography | Identify when a package retrieves hidden data from an image and executes it |
| code-execution | Identify when an OS command is executed in the setup.py file |
| unicode | Identify suspicious unicode characters |
| cmd-overwrite | Identify when the 'install' command is overwritten in setup.py, indicating a piece of code automatically running when the package is installed |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |

Metadata heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| empty_information | Identify packages with an empty description field |
| release_zero | Identify packages with an release version that's 0.0 or 0.0.0 |
| typosquatting | Identify packages that are named closely to an highly popular package |
| potentially_compromised_email_domain | Identify when a package maintainer e-mail domain (and therefore package manager account) might have been compromised |
| unclaimed_maintainer_email_domain | Identify when a package maintainer e-mail domain (and therefore npm account) is unclaimed and can be registered by an attacker |
| repository_integrity_mismatch | Identify packages with a linked GitHub repository where the package has extra unexpected files |
| single_python_file | Identify packages that have only a single Python file |
| bundled_binary | Identify packages bundling binaries |
| deceptive_author | This heuristic detects when an author is using a disposable email |


### npm

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| npm-serialize-environment | Identify when a package serializes 'process.env' to exfiltrate environment variables |
| npm-obfuscation | Identify when a package uses a common obfuscation method often used by malware |
| npm-silent-process-execution | Identify when a package silently executes an executable |
| shady-links | Identify when a package contains an URL to a domain with a suspicious extension |
| npm-exec-base64 | Identify when a package dynamically executes code through 'eval' |
| npm-install-script | Identify when a package has a pre or post-install script automatically running commands |
| npm-steganography | Identify when a package retrieves hidden data from an image and executes it |
| npm-dll-hijacking | Identifies when a malicious package manipulates a trusted application into loading a malicious DLL |
| npm-exfiltrate-sensitive-data | Identify when a package reads and exfiltrates sensitive data from the local system |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |

Metadata heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| empty_information | Identify packages with an empty description field |
| release_zero | Identify packages with an release version that's 0.0 or 0.0.0 |
| potentially_compromised_email_domain | Identify when a package maintainer e-mail domain (and therefore package manager account) might have been compromised; note that NPM's API may not provide accurate information regarding the maintainer's email, so this detector may cause false positives for NPM packages. see https://www.theregister.com/2022/05/10/security_npm_email/ |
| unclaimed_maintainer_email_domain | Identify when a package maintainer e-mail domain (and therefore npm account) is unclaimed and can be registered by an attacker; note that NPM's API may not provide accurate information regarding the maintainer's email, so this detector may cause false positives for NPM packages. see https://www.theregister.com/2022/05/10/security_npm_email/ |
| typosquatting | Identify packages that are named closely to an highly popular package |
| direct_url_dependency | Identify packages with direct URL dependencies. Dependencies fetched this way are not immutable and can be used to inject untrusted code or reduce the likelihood of a reproducible install. |
| npm_metadata_mismatch | Identify packages which have mismatches between the npm package manifest and the package info for some critical fields |
| bundled_binary | Identify packages bundling binaries |
| deceptive_author | This heuristic detects when an author is using a disposable email |


### go

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| shady-links | Identify when a package contains an URL to a domain with a suspicious extension |
| go-exec-base64 | Identify Base64-decoded content being passed to execution functions in Go |
| go-exfiltrate-sensitive-data | This rule identifies when a package reads and exfiltrates sensitive data from the local system. |
| go-exec-download | This rule downloads and executes a remote binary after setting executable permissions. |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |

Metadata heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| typosquatting | Identify packages that are named closely to an highly popular package |


### GitHub Action

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| npm-serialize-environment | Identify when a package serializes 'process.env' to exfiltrate environment variables |
| npm-obfuscation | Identify when a package uses a common obfuscation method often used by malware |
| npm-silent-process-execution | Identify when a package silently executes an executable |
| shady-links | Identify when a package contains an URL to a domain with a suspicious extension |
| npm-exec-base64 | Identify when a package dynamically executes code through 'eval' |
| npm-install-script | Identify when a package has a pre or post-install script automatically running commands |
| npm-steganography | Identify when a package retrieves hidden data from an image and executes it |
| npm-dll-hijacking | Identifies when a malicious package manipulates a trusted application into loading a malicious DLL |
| npm-exfiltrate-sensitive-data | Identify when a package reads and exfiltrates sensitive data from the local system |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |
### Extension

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| npm-serialize-environment | Identify when a package serializes 'process.env' to exfiltrate environment variables |
| npm-obfuscation | Identify when a package uses a common obfuscation method often used by malware |
| npm-silent-process-execution | Identify when a package silently executes an executable |
| shady-links | Identify when a package contains an URL to a domain with a suspicious extension |
| npm-exec-base64 | Identify when a package dynamically executes code through 'eval' |
| npm-install-script | Identify when a package has a pre or post-install script automatically running commands |
| npm-steganography | Identify when a package retrieves hidden data from an image and executes it |
| npm-dll-hijacking | Identifies when a malicious package manipulates a trusted application into loading a malicious DLL |
| npm-exfiltrate-sensitive-data | Identify when a package reads and exfiltrates sensitive data from the local system |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |
### RubyGems

Source code heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| rubygems-code-execution | Identify when a gem executes OS commands |
| rubygems-exfiltrate-sensitive-data | Identify when a package reads and exfiltrates sensitive data from the local system |
| rubygems-serialize-environment | Identify when a package serializes ENV to exfiltrate environment variables |
| rubygems-network-on-require | Identify when a gem makes network requests when required |
| rubygems-install-hook | Identify when a gem registers installation hooks |
| rubygems-exec-base64 | Identify when a package dynamically executes base64-encoded code |
| suspicious_passwd_access_linux | Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting |

Metadata heuristics:

| **Heuristic** | **Description** |
|:-------------:|:---------------:|
| typosquatting | Identify packages that are named closely to an highly popular package |
| empty_information | Identify packages with an empty description field |
| release_zero | Identify packages with an release version that's 0.0 or 0.0.0 |
| bundled_binary | Identify packages bundling binaries |
| repository_integrity_mismatch | Identify packages with a linked GitHub repository where the package has extra unexpected files |


<!-- END_RULE_LIST -->

## Writing Custom Rules

GuardDog supports custom rules in both [Semgrep](https://github.com/semgrep/semgrep) and [YARA](https://github.com/VirusTotal/yara) formats. Rules live under the [guarddog/analyzer/sourcecode](guarddog/analyzer/sourcecode) directory.

* **Semgrep rules** (`.yml`): Language-dependent, imported when language matches the selected ecosystem
* **YARA rules** (`.yar`): Language-agnostic, all rules are imported

### Metadata Schema for Risk-Based Scoring

To participate in GuardDog's risk correlation and scoring, rules must include specific metadata:

#### Required Fields

```yaml
identifies: "capability.{category}[.{specificity}]"  # or "threat.{category}[.{specificity}]"
severity: "low" | "medium" | "high"
mitre_tactics: ["tactic1", "tactic2"]  # MITRE ATT&CK tactics
description: "Human-readable description"
```

#### Optional Fields (default to `medium`)

```yaml
specificity: "low" | "medium" | "high"       # Pattern specificity
sophistication: "low" | "medium" | "high"    # Technique advancement level
```

### Understanding `identifies`

The `identifies` field determines how rules participate in risk formation:

**Format:** `{type}.{category}[.{specificity}]`

- **Type**: `capability` (what code *can* do) or `threat` (suspicious indicator)
- **Category**: `network`, `filesystem`, `process`, or `runtime`
- **Specificity** (optional): Adds detail like `outbound`, `read`, `obfuscation`

**Examples:**
- `capability.network` - General network capability
- `capability.network.outbound` - Specific outbound network capability
- `threat.filesystem.read` - Threat involving filesystem reads
- `threat.runtime.obfuscation` - Runtime threat (needs no capability)

### Risk Formation

**Risks form when capability + threat match in the same file:**

1. **Same category**: `network` + `network`, `filesystem` + `filesystem`
2. **Specificity compatibility**:
   - General matches specific: `threat.network` + `capability.network.outbound` ✅
   - Exact match: `threat.network.outbound` + `capability.network.outbound` ✅
   - Conflict: `threat.network.outbound` + `capability.network.inbound` ❌

3. **Exception**: `threat.runtime.*` rules automatically form risks without needing a capability

### YARA Rule Example

```yara
rule sample_threat_rule {
  meta:
    identifies = "threat.category.specificity"
    severity = "high"
    mitre_tactics = ["execution", "defense-evasion"]
    specificity = "high"
    sophistication = "medium"
    description = "Description of what this detects"

  strings:
    $pattern1 = "suspicious_pattern"
    $pattern2 = /regex[0-9]+/

  condition:
    any of them
}
```

```yara
rule sample_capability_rule {
  meta:
    identifies = "capability.category"
    severity = "low"
    mitre_tactics = []  # Capabilities typically don't map to tactics
    description = "Detects a code capability"

  strings:
    $api_call = "api_function"

  condition:
    $api_call
}
```

### Semgrep Rule Example

```yaml
rules:
  - id: sample-rule
    languages:
      - python
    message: Output message when rule matches
    metadata:
      identifies: "threat.category.specificity"
      severity: "high"
      mitre_tactics: ["execution"]
      specificity: "high"
      sophistication: "medium"
      description: "Description used in the CLI help"
    patterns:
      - pattern: suspicious_code_pattern(...)
    severity: WARNING
```

### Metadata Guidelines

**Severity** (impact of finding):
- `low`: Minor concern, common patterns
- `medium`: Moderately suspicious
- `high`: Clearly malicious or high impact

**Specificity** (how specific the pattern is to malware vs legitimate code):
- `low`: Generic patterns that appear in legitimate code frequently
- `medium`: Reasonably specific, some false positives expected
- `high`: Very specific to that kind of threat, minimal false positives

**Sophistication** (technique advancement):
- `low`: Basic/common techniques
- `medium`: Moderate evasion or complexity
- `high`: Advanced techniques, APT-level

**MITRE Tactics** (attack stages, order matters):
- **Early stage**: `initial-access`, `execution`, `reconnaissance`
- **Mid stage**: `defense-evasion`, `credential-access`, `persistence`, `privilege-escalation`
- **Late stage**: `command-and-control`, `exfiltration`, `impact`, `lateral-movement`

First tactic is primary for scoring. List multiple tactics if detection is ambiguous.

### Testing Rules

After creating your rule file (ensure filename matches rule ID), test it:

```bash
# Scan with specific rules
guarddog pypi scan package-name --rules my-rule

# Exclude specific rules
guarddog pypi scan package-name --exclude-rules my-rule
```

Note: Rule ID must match the filename (without extension)

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

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install GuardDog
        run: pip install guarddog

      - run: guarddog pypi verify requirements.txt --output-format sarif --exclude-rules repository_integrity_mismatch > guarddog.sarif

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
