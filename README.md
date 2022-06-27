# PyPI Package Malware Scanner
The PyPI Package Malware Scanner offers a CLI command that scans a PyPI package version for user-specified malware flags. 
A set of predefined rules based on package registry metadata and source code analysis are used as heuristics to find malware-ridden packages.

CLI Command Example: \
`python3 scan.py -n requests [-v 2.28.0 -r 0 2 5 6]`\
`python3 scan.py --package-name requests [--version 2.28.0 --rules exec maintainers 5 6]`

- [PyPI Package Malware Scanner](#pypi-package-malware-scanner)
  - [Introduction](#introduction)
  - [Heuristics](#heuristics)
      - [Registry Metadata Analysis](#registry-metadata-analysis)
      - [Source Code Analysis](#source-code-analysis)

## Introduction
Software supply chain security is a hot topic right now. There are a lot of ways to model supply chain security, but [SLSA](https://slsa.dev/spec/v0.1/index) has a great diagram of a high level threat model on their website.

For the sake of this research, I’d like to focus on E - Using a risky dependency. Datadog is building a Risky Dependency product by first tracking how customers use and load potentially vulnerable dependencies via APM Backend architecture for VM.  

There are risks other than vulnerabilities within 3rd-party dependencies. For example, the company Socket has a [suite of detections](https://docs.google.com/document/d/1FW_sDMQjwFr1M9rJtUCl-FGd9Qx-fSPTkGEhlrze6eE/edit#heading=h.c7o1wqxf0xx) they find for npm packages. For this project, we will explore the different threats affecting 3rd-party dependencies in popular package management frameworks, gain an expert level understanding of these frameworks, build a tool to download and scan packages from these frameworks and flag packages based on different risk heuristics. 

Once we identify how packages are being downloaded from registries, we should take time to document different attack and defense techniques people have employed to protect (or attack) these registries. We will do this by writing content “hackingthe.supply”, which is a website dedicated to highlighting attack & defend techniques against the software supply chain. This was inspired by hackingthe.cloud. We will only write content for a very specific part of hackingthe.supply.

## Heuristics
Heuristics are separated into two categories: registry metadata analysis and source code analysis. Registry metadata pertains to the metrics of a given package on the PyPI registry (ex. number of maintainers, popularity, similarity in package names, gaps in code pushing), while source code analysis investigates the actual code of the package. The malicious packages analyzed to guide these heuristics are listed here: [PyPI Malware Analysis](https://datadoghq.atlassian.net/wiki/spaces/~628e8c561a437e007042ec14/pages/2515534035/PyPI+Malware+Analysis).

#### Registry Metadata Analysis
The registry metadata analysis looks for the flags detailed in the paper here: https://arxiv.org/pdf/2112.10165.pdf

| Rule | Reason | Heuristic | Examples |
|---|---|---|---|
| Expired maintainer domain | Attackers can purchase an expired domain and hijack an account | Make a GET request to Godaddy's API to check if a maintainer domain is available | ctx |
| Unmaintained packages | These packages host more vulnerabilities that an attacker can exploit | Check last update. If a gap in updates spans more than two years, mark as unmaintained | event-stream |

#### Source Code Analysis
| Rule | Reason | Heuristic | Examples |
|---|---|---|---|
| Typosquatting | Most common way attackers get developers to install their package | Check for distance one Levenshtein distance, check for swapped terms around hyphens, check if package name is a substring of more popular packages, check for lookalike letters | (Too many to name) |
| Install command overwritten in setup.py | Custom scripts for "pip install" in setup.py allows attackers to run privileged scripts immediately when their package is installed | Semgrep instances of `cmdclass = {"install": [new script]}` in the `setup(...)` function in setup.py | httplib3, htpplib2, request-oathlib, unicode-csv, etc. |
| Hardcoded base64 encoded strings | Common obfuscation tactic | Semgrep instances of base64 decoding functions. Regex base64 rules on the literal metavariable to determine if variable was hardcoded | colourama, httplib3, request-oathlib, unicode-csv, etc. |
| Evaluation of strings | Attackers commonly execute privileged bash commands and other scripts through `exec`/`eval`/`subprocess.getoutput` commands | Semgrep for `exec`/`eval`/`subprocess.getoutput` functions | colourama, loglib-modules, pzymail |
| Suspicious domains | Attackers often use cheap, unencrypted domains to store scripts or to send POST requests containing sensitive information. The domain extension "de" is common, and links are obscured with base64 encoding or bit.ly links. | Semgrep for "http" instead of "https", suspcious domain extensions like "de" and "xyz", base64 encoded links, and bit.ly links. | pzymail, py-jwt, pyjtw, tenserflow, etc. |
| Creating executable in setup.py | setup.py can be used as a gateway to execute other dangerous Python scripts, often fetched from the attacker's server using a GET request | Use Semgrep to hunt for function calls that create executable files | distrib, colourama, pzymail |
| Accessing system information | Attackers collect information by recording env vars, ip addresses, usernames, os information, etc. and sending this data to their server. | Use Semgrep source/sink searching to hunt for variables that record system information using os/platform/socket/etc. modules | distrib, loglib-modules, tenserflow |

