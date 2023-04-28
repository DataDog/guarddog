#!/bin/sh

runtest="$1"

if [ -z "$runtest" ]; then
	echo "Add argument to specify the tests (false_positive, false_negative, all)"
	exit 0
fi

if [ "$runtest" = "false_positive" ] || [ "$runtest" = "all" ]; then
	echo "## Test - False Positives"
	guarddog pypi scan "$LEGIT_PYPI_PACKAGE" --output-format json | jq -c '.[]' | grep -v '"issues":0' 
fi

if [ "$runtest" = "false_negative" ] || [ "$runtest" = "all" ]; then
	echo "## Test - False Negatives"
	guarddog pypi scan "$MALICIOUS_PYPI_PACKAGE" --output-format json | jq -c '.[]' | grep '"issues":0'
fi


