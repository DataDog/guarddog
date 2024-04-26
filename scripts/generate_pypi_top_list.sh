#!/bin/bash

curl "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json" | \
    jq '.' > guarddog/analyzer/metadata/resources/top_pypi_packages.json