.PHONY: test test-semgrep-rules test-metadata-rules

test: test-semgrep-rules test-metadata-rules

test-semgrep-rules:
	semgrep --metrics off --quiet --test --config guarddog/analyzer/sourcecode tests/analyzer/sourcecode

test-metadata-rules:
	python -m pytest
