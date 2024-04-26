#!/bin/bash

echo -n > guarddog/analyzer/metadata/resources/top_npm_packages.json
for run in {1..50}; do \
    curl https://sandworm.dev/npm/packages/${run} | \
        egrep -oE "(<a href=\"https://sandworm.dev/npm/package/.*?>).*?(?:</a>)" | \
        cut -d '>' -f2 | cut -d '<' -f1 >> guarddog/analyzer/metadata/resources/top_npm_packages.json; 
done; 
npmdata=$(< guarddog/analyzer/metadata/resources/top_npm_packages.json)
echo -n "${npmdata}" | \
    jq -R -n ' { last_update: now | todateiso8601, rows: [ inputs | { project:. } ] } ' > guarddog/analyzer/metadata/resources/top_npm_packages.json