.PHONY: test test-semgrep-rules test-metadata-rules test-core docs

test: test-semgrep-rules test-metadata-rules test-core coverage-report

type-check:
	mypy --install-types --non-interactive guarddog

lint:
	flake8 guarddog --count --select=E9,F63,F7,F82 --show-source --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data
	flake8 guarddog --count --max-line-length=120 --statistics --exclude tests/analyzer/sourcecode,tests/analyzer/metadata/resources,evaluator/data --ignore=E203,W503

test-semgrep-rules:
	semgrep --metrics off --quiet --test --config guarddog/analyzer/sourcecode tests/analyzer/sourcecode

test-metadata-rules:
	COVERAGE_FILE=.coverage_metadata coverage run -m pytest tests/analyzer/metadata

test-core:
	COVERAGE_FILE=.coverage_core coverage run -m pytest tests/core

coverage-report:
	coverage combine .coverage_metadata .coverage_core
	coverage report

docs:
	python scripts/generate-rules-docs.py README.md

update-top-pkg-list:
	curl "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json" | jq '.' > guarddog/analyzer/metadata/resources/top_pypi_packages.json
	
	curl "https://anvaka.github.io/npmrank/online/npmrank.json" | \
		jq -r '[ .rank | keys[] as $$k |  {project:$$k, rank:.[$$k] }  ] | sort_by(.rank) | reverse | .[0:5000] | { last_update: now | todateiso8601, rows: . }' \
			> guarddog/analyzer/metadata/resources/top_npm_packages.json