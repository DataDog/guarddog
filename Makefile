.PHONY: test test-semgrep-rules test-metadata-rules test-core

test: test-semgrep-rules test-metadata-rules test-core

type-check:
	mypy --install-types --non-interactive guarddog

lint:
	flake8 guarddog --count --select=E9,F63,F7,F82 --show-source --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data
	flake8 guarddog --count --max-line-length=120 --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data --ignore=E203,W503

test-semgrep-rules:
	semgrep --metrics off --quiet --test --config guarddog/analyzer/sourcecode tests/analyzer/sourcecode

test-metadata-rules:
	python -m pytest tests/analyzer/metadata

test-core:
	python -m pytest tests/core
