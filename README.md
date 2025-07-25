# GuardDog

[![Test](https://github.com/DataDog/guarddog/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/test.yml) [![Static analysis](https://github.com/DataDog/guarddog/actions/workflows/semgrep.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/semgrep.yml)

<p align="center">
  <img src="./docs/images/logo.png" alt="GuardDog" width="300" />
</p>

GuardDog is a CLI tool that allows to identify malicious PyPI and npm packages, Go modules, GitHub actions, or VSCode extensions. It runs a set of heuristics on the package source code (through Semgrep rules) and on the package metadata.

GuardDog can be used to scan local or remote PyPI and npm packages, Go modules, GitHub actions, or VSCode extensions using any of the available [heuristics](#heuristics).

It downloads and scans code from:

* NPM: Packages hosted in [npmjs.org](https://www.npmjs.com/)
* PyPI: Source files (tar.gz) packages hosted in [PyPI.org](https://pypi.org/)
* Go: GoLang source files of repositories hosted in [GitHub.com](https://github.com)
* GitHub Actions: Javascript source files of repositories hosted in [GitHub.com](https://github.com)
* VSCode Extensions: Extensions (.vsix) packages hosted in [marketplace.visualstudio.com](https://marketplace.visualstudio.com/)

![GuardDog demo usage](docs/images/demo.png)

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

# All the commands also work on npm, go
guarddog npm scan express

guarddog go scan github.com/DataDog/dd-trace-go

guarddog go verify /tmp/repo/go.mod

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
| cmd-overwrite | Identify when the 'install' command is overwritten in setup.py, indicating a piece of code automatically running when the package is installed |

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
<!-- END_RULE_LIST -->

## Custom Rules

Guarddog allows to implement custom sourcecode rules.
Sourcecode rules live under the [guarddog/analyzer/sourcecode](guarddog/analyzer/sourcecode) directory, and supported formats are [Semgrep](https://github.com/semgrep/semgrep) or [Yara](https://github.com/VirusTotal/yara).

* Semgrep rules are language-dependent, and Guarddog will import all `.yml` rules where the language matches the ecosystem selected by the user in CLI.
* Yara rules on the other hand are language agnostic, therefore all matching `.yar` rules present will be imported.

Is possible then to write your own rule and drop it into that directory, Guarddog will allow you to select it or exclude it as any built-in rule as well as appending the findings to its output.

For example, you can create the following semgrep rule:
```yaml
rules:
  - id: sample-rule
    languages:
      - python
    message: Output message when rule matches
    metadata:
      description: Description used in the CLI help
    patterns:
        YOUR RULE HEURISTICS GO HERE
    severity: WARNING
```

Then you'll need to save it as `sample-rule.yml` and note that the id must match the filename

In the case of Yara, you can create the following rule:
```
rule sample-rule
{
  meta:
    description = "Description used in the output message"
    target_entity = "file"
  strings:
    $exec = "exec"
  condition:
    1 of them
}
```
Then you'll need to save it as `sample-rule.yar`.

Note that in both cases, the rule id must match the filename

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

#### Using pip

* Ensure `>=python3.10` is installed
* Clone the repository
* Create a virtualenv: `python3 -m venv venv && source venv/bin/activate`
* Install requirements: `pip install -r requirements.txt`
* Run GuardDog using `python -m guarddog`

#### Using poetry

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

### Semgrep configuration

Guarddog uses `Semgrep`, a powerful static analysis tool that scans code for patterns. 

The `max_target_bytes` setting, which controls the maximum size of a file that Semgrep will analyze, can be adjusted using the environment variable `GUARDDOG_SEMGREP_MAX_TARGET_BYTES`. 
By default, this value is set to 10MB; files exceeding this limit will be skipped during analysis to optimize performance and resource usage.

Additionally, the timeout setting, which specifies the maximum time in seconds that Semgrep will spend running a rule on a single file,  can be configured via the `GUARDDOG_SEMGREP_TIMEOUT` environment variable. The default value is 10 seconds.


## Maintainers

Authors:
* [Ellen Wang](https://www.linkedin.com/in/ellen-wang-4bb5961a0/)
* [Christophe Tafani-Dereeper](https://github.com/christophetd)
* [Vladimir de Turckheim](https://www.linkedin.com/in/vladimirdeturckheim/)
* [Sebastian Obregoso](https://www.linkedin.com/in/sebastianobregoso/)

## Acknowledgments

Inspiration:
* [Backstabber’s Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://arxiv.org/pdf/2005.09535)
* [What are Weak Links in the npm Supply Chain?](https://arxiv.org/pdf/2112.10165.pdf)
* [A Survey on Common Threats in npm and PyPi Registries](https://arxiv.org/pdf/2108.09576.pdf)
* [A Benchmark Comparison of Python Malware Detection Approaches](https://arxiv.org/pdf/2209.13288.pdf)
* [Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages](https://arxiv.org/pdf/2002.01139)
