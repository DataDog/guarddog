#!/bin/sh

runtest="$1"
scan_dir="$2"

if [ -z "$runtest" ] || [ -z "$scan_dir" ]; then
	echo "Add argument to specify the tests you want to do (false_positive, false_negative, all)"
	echo "and add a directory to scan"
	exit 0
fi

if [ "$runtest" = "false_positive" ] || [ "$runtest" = "all" ]; then
	echo "[+] ## Test - False Positives"
	guarddog pypi scan "${scan_dir}" --output-format json | jq -c '.[]' | grep -v '"issues":0' > false_positive_result.json
	echo "[+] Result exported in false_positive_result.json"
fi

if [ "$runtest" = "false_negative" ] || [ "$runtest" = "all" ]; then
	echo "[+] ## Test - False Negatives"
	guarddog pypi scan "${scan_dir}" --output-format json | jq -c '.[]' | grep '"issues":0' > false_negative_result.json
	echo "[+] Result exported in false_negative_result.json"
fi


