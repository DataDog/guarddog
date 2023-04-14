#!/bin/sh

GITHUB_REPO="https://github.com/DataDog/malicious-software-packages-dataset.git"

output_dir="$1"
if [ -z "$output_dir" ]; then
	echo "Please specify the output directory"
	exit 0
fi

# Download ~954 malicious pypi packages
git clone ${GITHUB_REPO} /tmp/malicious-dataset
mv /tmp/malicious-dataset/samples/pypi/ ${output_dir}
rm -rf /tmp/malicious-dataset
