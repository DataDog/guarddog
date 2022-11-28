# Programmatic use

GuardDog can be used as a Python library:

```python
from guarddog import PackageScanner

scanner = PackageScanner()

results = scanner.scan_remote('guarddog')
print(results)
```

This will download the package `guarddog`, scan it and cleanup the directory from the disk.

## API

### Class `PackageScanner`

Scans package for attack vectors based on source code and metadata rules.
```python
from guarddog import PackageScanner
```

#### Method `scan_remote(self, name, version=None, rules=None, base_dir=None, write_package_info=False)`

Scans a remote package

Arguments:
* name (str): name of the package on PyPI
* version (str, optional): version of package (ex. 0.0.1)
* rules (set, optional): Set of rule names to use. Defaults to all rules.
* base_dir (str, optional): directory to use to download package. There will be no cleanup after the scan.
* write_package_info (bool, default False): if set to true, the result of the metadata API will be writen to a json file

##### Example

```python
from guarddog import PackageScanner

scanner = PackageScanner()

with tempfile.TemporaryDirectory() as tmpdirname:
    results = scanner.scan_remote(package, version, None, tmpdirname, True)  # fixing the dir prevents the cleanup
    print(f"Found {results['issues']} issues on package {package}")
    if results["issues"] > 0:
        upload_scan_artifacts(s3, scan_key, results["path"], tmpdirname)
```
In this example, GuardDog will download and scan the package defined by `package` and `version`. It will use a provided
temporary directory and write the Pypi metadata of the package in a JSON file.
This can be used, for instance, to upload the findings in a specific place for review.
