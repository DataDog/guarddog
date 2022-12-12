# Programmatic usage

GuardDog can be used as a Python library:

```python
from guarddog import PypiPackageScanner

scanner = PypiPackageScanner()

results = scanner.scan_remote('requests')
print(results)
```

This will download the package `requests`, scan it, then cleanup the temporary directory from disk.

## API

### Class `PypiPackageScanner` and Class `NPMPackageScanner`

Scans package for attack vectors based on [source code](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/sourcecode) and [metadata](https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/metadata) heuristics.

```python
from guarddog import PypiPackageScanner
```

#### Method `scan_remote(self, name, version=None, rules=None, base_dir=None, write_package_info=False)`

Scans a remote package

Arguments:
* `name` (str): name of the package on PyPI
* `version` (str, optional): version of package (ex. 0.0.1). If not specified, the latest version is assumed.
* `rules` (set, optional): Set of rule names to use. Defaults to all rules.
* `base_dir` (str, optional): directory to use to download package to. If not specified, a temporary folder is created and cleaned up automatically. If not specified, the provided directory is not removed after the scan.
* `write_package_info` (bool, default False): if set to true, the result of the PyPI metadata API is written to a JSON file where the package is downloaded.

Example:

```python
from guarddog import PypiPackageScanner

scanner = PypiPackageScanner()

with tempfile.TemporaryDirectory() as tmpdirname:
    results = scanner.scan_remote(package, version, None, tmpdirname, True)  # fixing the dir prevents the cleanup
    print(f"Found {results['issues']} issues on package {package}")
    if results["issues"] > 0:
        upload_scan_artifacts(s3, scan_key, results["path"], tmpdirname)
```
In this example, GuardDog will download and scan the package defined by `package` and `version`. It will use a provided
temporary directory and write the Pypi metadata of the package in a JSON file.
This can be used, for instance, to upload the findings in a specific place for review.

To scan a npm package, importing `NPMPackageScanner` instead of `PypiPackageScanner` will work.
