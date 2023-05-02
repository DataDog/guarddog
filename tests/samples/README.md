# Benchmarking

The purpose of this directory is to run guarddog on legit and malicious packages 
to get a ratio of false positives and false negatives.

## Getting started
### Local test

```sh
# Download legit packages in the legit_pypi_package folder
/bin/sh ./download_legit_pypi_package.sh ./legit_pypi_package/

# /!\ This part can trigger antivirus /!\ to avoid it, you can use the container
# Download malicious packages in the malicious_pypi_package folder
/bin/sh ./download_malicious_pypi_package.sh ./malicious_pypi_package/

# Test false positives and get the result in false_positive_result.json
/bin/sh local_run_test.sh false_positive ./legit_pypi_package/

# Test false negatives and get the result in false_negative_result.json
/bin/sh local_run_test.sh false_negative ./malicious_pypi_package/

# Run both test on a directory and get the result in the same file as mentioned above 
/bin/sh local_run_test.sh all ./your-directory

```

### Container test

Using the docker will take more time to scan than the local tests

```sh
# build the container
docker build . -t guarddog_benchmark

# Test false positives
docker run --rm guarddog_test false_positive > false_positive_result.json

# Test false negatives
docker run --rm guarddog_test false_negative > false_negative_result.json

# Test both 

docker run --rm guarddog_test all > all_result.json
```

