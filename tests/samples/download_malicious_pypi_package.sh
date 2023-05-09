#!/bin/sh

GITHUB_REPO="https://github.com/DataDog/malicious-software-packages-dataset.git"

if [ -z "$1" ] ; then
	echo "Please specify an output directory"
	exit 0
fi
output_dir="$(realpath -q "$1")"
mkdir -p "${output_dir}"

# Download ~1000 malicious pypi packages
echo "[+] Cloning repo"
git clone --depth 1 ${GITHUB_REPO} /tmp/malicious-dataset
cd /tmp/malicious-dataset/samples/pypi/ 

echo "[+] Decrypting samples"
/bin/sh extract.sh "${output_dir}"
rm -rf /tmp/malicious-dataset
