## PyPI Package Malware Scanner
The PyPI Package Malware Scanner offers a CLI command that scans a PyPI package version for user-specified malware flags. 
A set of predefined rules based on package registry metadata and source code analysis are used as heuristics to find malware-ridden packages.


- [PyPI Package Malware Scanner](#pypi-package-malware-scanner)
  - [Getting Started](#getting-started)
    - [CLI Reference](#cli-reference)
  - [Installing Pysecurity](#installing-pysecurity)
    - [Testing](#testing)
  - [Heuristics](#heuristics)
    - [Accuracy of Heuristics](#accuracy-of-heuristics)
      - [Methodology](#methodology)
    - [Registry Metadata Analysis](#registry-metadata-analysis)
    - [Source Code Analysis](#source-code-analysis)


### Getting Started
Pysecurity can be used to scan local or remote PyPI packages using any of the available [rules](#heuristics). Here's how to use pysecurity:

#### CLI Reference
The structure for scanning a package is:

```sh
$ python3 -m pysecurity -n [NAME] -v [VERSION] -r [RULES]

# Scan the most recent version
$ python3 -m pysecurity scan setuptools 

# Scan a specific version
$ python3 -m pysecurity scan setuptools -v 63.6.0 

# Scan a local package
$ python3 -m pysecurity scan local ./Desktop/packagename 

# Scan using a subset of the rules
$ python3 -m pysecurity scan setuptools -v 63.6.0 -r code-execution -r shady-links 
```

Note that to scan specific rules, use multiple `-r` flags.


### Installing Pysecurity
Pysecurity is not yet packaged. To run in the development environment, check out [CONTRIBUTING](CONTRIBUTING.md)

#### Testing

To run the semgrep rules against the test cases:

```sh
$ semgrep --metrics off --quiet --test --config pysecurity/analyzer/sourcecode pysecurity_tests/semgrep
```

To find the precision and recall of the rules, run: 
```sh
$ python3 pysecurity_tests/evaluator/evaluator.py
```
This will calculate the false positive, false negative, true positive, and true negative rates from logs in `pysecurity_tests/evaluator/logs` folder, which contains the results of scanning the `data` folder.

Running the command above ***will not scan*** the directories. To scan, uncomment line 351 `metric_generator.scan()` in `pysecurity_tests/evaluator/evaluator.py`. Then, run the command again.

### Heuristics
Heuristics are separated into two categories: registry metadata analysis and source code analysis. Registry metadata pertains to the metrics of a given package on the PyPI registry (ex. number of maintainers, popularity, similarity in package names, gaps in code pushing), while source code analysis investigates the actual code of the package. The malicious packages analyzed to guide these heuristics are listed here: [PyPI Malware Analysis](https://datadoghq.atlassian.net/wiki/spaces/~628e8c561a437e007042ec14/pages/2515534035/PyPI+Malware+Analysis).

#### Accuracy of Heuristics
The precision, recall, and false positive rate of each rule was measured using the methods described in [Testing](#testing). The precision, recall, and false positive rates achieved are:

| Rule | Precision | Recall | FP |
|---|---|---|---|
|cmd-overwrite|0.429|1.0|0.015|
|code-execution|0.0769|1.0|0.035|
|download-executable|1.0|1.0|0.0|
|exec-base64|0.5|1.0|0.001|
|exfiltrate-sensitive-data|0.526|1.0|0.012|
|shady-links|0.186|1.0|0.017|
|typosquatting|0.958|0.719|0.0|

The typosquatting rule ignored the top 5000 downloaded packages (in the past month), so all error is from missed typosquatting while scanning malware.

##### Methodology
The precision and recall of each rule was measured by running the tool on the 1000 most downloaded PyPI packages (benign data) and a collection of about 30-40 pieces of malware that were removed from PyPI (malicious data). Every line in the top 1000 packages is considered to be safe, so any lines flagged there is considered a false positive. In the malicious dataset, dangerous lines were hand-labeled in `malicious_ground_truth.json` and compared to the actual result. Any discrepencies were classified as a false-negative (missed line in ground truth), true-positive (matches ground truth), or false-positive (extra line compared to ground truth). The precision and recall were calculated from these metrics. 
<br/>
The false positive rate used only the benign dataset, using package-level granularity. Any lines detected in a package marked the package as a false-positive. Meanwhile, if no lines were detected in the package, it was marked as a true-negative. The difference in granulary compared to precision/recall is a result of being unable to measure the number of lines in the benign dataset.

#### Registry Metadata Analysis
The registry metadata analysis looks for the flags detailed in the paper here: https://arxiv.org/pdf/2112.10165.pdf

| Rule | Reason | Heuristic | Examples |
|---|---|---|---|
| Typosquatting | Most common way attackers get developers to install their package | Check for distance one Levenshtein distance, check for swapped terms around hyphens, check if package name is a substring of more popular packages, check for lookalike letters | (Too many to name) |
<!-- | Expired maintainer domain | Attackers can purchase an expired domain and hijack an account | Make a GET request to Godaddy's API to check if a maintainer domain is available | ctx |
| Unmaintained packages | These packages host more vulnerabilities that an attacker can exploit | Check last update. If a gap in updates spans more than two years, mark as unmaintained | event-stream | -->

#### Source Code Analysis
| Rule | Reason | Heuristic | Examples |
|---|---|---|---|
| **cmd-overwritten** <br/><br/> Install command overwritten in setup.py | Custom scripts for "pip install" in setup.py allows attackers to run privileged scripts immediately when their package is installed | Semgrep instances of `cmdclass = {"install": [new script]}`, or other equivalents, in the `setup(...)` function in setup.py | httplib3, htpplib2, request-oathlib, unicode-csv, etc. |
| **exec-base64** <br/><br/> Executing hardcoded base64 encoded strings | Common obfuscation tactic | Semgrep instances of base64 decoding functions and use source/sink to determine if evaluated | colourama, httplib3, request-oathlib, unicode-csv, etc. |
| **code-execution** <br/><br/> Executing code or spawning processes | Attackers commonly execute privileged bash commands and other scripts through `exec`/`eval`/`subprocess.getoutput` and other commands | Semgrep for functions like `exec`/`eval`/`subprocess.getoutput` and filter out benign commands like `git` or `pip freeze` | colourama, loglib-modules, pzymail |
| **shady-links** <br/><br/> Suspicious domains | Attackers often use free domains or url shorteners to store scripts or to send POST requests containing sensitive information. | Semgrep for suspcious domain extensions like "link" and "xyz", in addition to bit.ly links. | pzymail, py-jwt, pyjtw, tenserflow, etc. |
| **download-executable** <br/><br/> Creating executable in setup.py | setup.py can be used as a gateway to execute other dangerous Python scripts, often fetched from the attacker's server using a GET request | Use Semgrep source/sink to hunt for function calls that fetch data (`request`), then create files from that data and change the file permissions (`os.chmod`) | distrib, colourama, pzymail |
| **exfiltrate-sensitive-data** <br/><br/> Spying on sensitive system information | Attackers collect information by recording env vars, ip addresses, usernames, os information, etc. and sending this data to their server. | Use Semgrep source/sink searching to hunt for variables that record system information using `os`/`platform`/`socket`/etc. modules | distrib, loglib-modules, tenserflow |

