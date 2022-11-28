.PHONY: test test-semgrep-rules test-metadata-rules test-core

test: test-semgrep-rules test-metadata-rules test-core

test-semgrep-rules:
	semgrep --metrics off --quiet --test --config guarddog/analyzer/sourcecode tests/analyzer/sourcecode

test-metadata-rules:
	python -m pytest tests/analyzer/metadata

test-core:
	python -m pytest tests/core
