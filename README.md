![GuardDog Banner](docs/images/banner.png)

[![Test](https://github.com/DataDog/guarddog/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/test.yml) [![Static analysis](https://github.com/DataDog/guarddog/actions/workflows/semgrep.yml/badge.svg)](https://github.com/DataDog/guarddog/actions/workflows/semgrep.yml)

GuardDog is a CLI tool that allows to identify malicious PyPI packages. It runs a set of heuristics on the package source code (through Semgrep rules) and on the package metadata.

GuardDog can be used to scan local or remote PyPI packages using any of the available [heuristics](#heuristics).

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

# Scan a local package
guarddog pypi scan /tmp/triage.tar.gz

# Scan every package referenced in a requirements.txt file of a local folder
guarddog pypi verify workspace/guarddog/requirements.txt

# Scan every package referenced in a requirements.txt file and output a sarif file - works only for verify
guarddog pypi verify --output-format=sarif workspace/guarddog/requirements.txt

# Output JSON to standard output - works for every command
guarddog pypi scan requests --output-format=json

# All the commands also work on npm
guarddog npm scan express
```


## Heuristics

GuardDog comes with 2 types of heuristics:

* [**Source code heuristics**](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/sourcecode): Semgrep rules running against the package source code.

* [**Package metadata heuristics**](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/metadata): Python heuristics running against the package metadata on PyPI.

### Source code heuristics


|                                                                         **Heuristic**                                                                         |                                                                            **Description**                                                                            |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|                       [Command overwrite](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/cmd-overwrite.yml)                       | The `install` command is overwritten in the `setup.py` file, indicating that a system command is automatically run when installing the package through `pip install`. |
|            [Dynamic execution of base64-encoded data](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/exec-base64.yml)             |                                          A base64-encoded string ends up being executed by a function like `exec` or `eval`                                           |
|            [Download of an executable to disk](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/download-executable.yml)            |                                          Data coming from an HTTP response ends up being written to disk and made executable                                          |
| [Exfiltration of sensitive data to a remote server](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/exfiltrate-sensitive-data.yml) |                                            Sensitive data from the environment ends up being sent through an HTTP request                                             |
|                 [Code execution in `setup.py`](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/code-execution.yml)                 |                                                 Code in `setup.py` executes code dynamically or starts a new process                                                  |
|                    [Unusual domain extension](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/shady-links.yml)                     |                                      Usage of a domain name with an extension frequently used by malware (e.g. `.xyz` or `.top`)                                      |
|        [Dynamic execution of hidden data from an image](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/steganography.yml)         |                                           The package uses steganography to extract a payload from an image and execute it                                            |
|               [Use of a common obfuscation method](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/obfuscation.yml)                |                            The package uses an obfuscation method commonly used by malware, such as running `eval` on hexadecimal strings                             |
|           [Silent execution of a process](https://github.com/DataDog/guarddog/blob/main/guarddog/analyzer/sourcecode/silent-process-execution.yml)            |                                                     The package spawns a subprocess without capturing its output                                                      |

### Package metadata heuristics

|                                  **Heuristic**                                  |                                                                                                                                                                                                   **Description**                                                                                                                                                                                                   |
|:-------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|                                  Typosquatting                                  |                                                                                                                                                                             Package has a name close to one of the top 5k PyPI packages                                                                                                                                                                             |
|                Potentially compromised maintainer e-mail domain                 | Maintainer e-mail address is associated to a domain that was re-registered later than the last package release. This can be an indicator that this is a custom domain that expired, and was leveraged by an attacker to compromise the package owner's PyPI account. See [here](https://therecord.media/thousands-of-npm-accounts-use-email-addresses-with-expired-domains) for a description of the issue for npm. |
|                            Empty package description                            |                                                                                                                                                                                      Package has an empty description of PyPI                                                                                                                                                                                       |
|                                  Release 0.0.0                                  |                                                                                                                                                                               Package has its latest release set to `0.0.0` or `0.0`                                                                                                                                                                                |
| Source code discrepancy between repository and release artifact  (experimental) |                                                                                                         The release artifact (e.g. PyPI package archive) has at least one file that differs from the original GitHub repository. This can indicate that the package release artifacts have been backdoored                                                                                                          |

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

### Adding new source code heuristics

TBD

### Adding new package metadata heuristics

TBD

## Acknowledgments

Authors: 
* [Ellen Wang](https://www.linkedin.com/in/ellen-wang-4bb5961a0/)
* [Christophe Tafani-Dereeper](https://github.com/christophetd)
* [Vladimir de Turckheim](https://www.linkedin.com/in/vladimirdeturckheim/)

Inspiration: 
* [What are Weak Links in the npm Supply Chain?](https://arxiv.org/pdf/2112.10165.pdf)
* [A Survey on Common Threats in npm and PyPi Registries](https://arxiv.org/pdf/2108.09576.pdf)
