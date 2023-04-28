#!/bin/sh

TOP_PYPI_PACKAGE="https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
REQUIREMENT_FILE="legit_top_packages.txt"

if [ -z "$1" ]; then
	echo "Please specify an output directory"
	exit 0
fi
output_dir=$(realpath -q "$1")
mkdir -p "${output_dir}"

# This url contains 5000 pypi packages but we'll only use the top 500
# Removing tensorflow and psycopg2 packages from the list
echo "[+] Retrieving the pypi packages list"
curl "${TOP_PYPI_PACKAGE}" | jq '.rows[].project' | tr -d "\"" | head -500 | grep -Ev "(tensorflow|psycopg2)" > ${REQUIREMENT_FILE}
echo "[+] Downloading pypi packages"
pip download --no-cache-dir --no-deps -r ${REQUIREMENT_FILE} --dest "${output_dir}"

