#!/bin/sh

TOP_PYPI_PACKAGE="https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
REQUIREMENT_FILE="legit_top_packages.txt"

output_dir="$1"
if [ -z "$output_dir" ]; then
	echo "Please specify the output directory"
	exit 0
fi

# This url contains 5000 pypi packages but we'll only use the top 500
curl "${TOP_PYPI_PACKAGE}" | jq '.rows[].project' | tr -d "\"" | head -500 | grep -Ev "(tensorflow|psycopg2)" > ${REQUIREMENT_FILE}
pip download --no-cache-dir --no-deps -r ${REQUIREMENT_FILE} --dest $output_dir

