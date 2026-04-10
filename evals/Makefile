PYTHON ?= uv run python3
WORKERS ?= 10
BENIGN_PACKAGES ?= 1000
SAMPLES_PER_ECO ?= 250
THRESHOLD ?= 5.0
ECOSYSTEMS ?= pypi npm

.PHONY: all precision recall report resample clean

all: precision recall report

precision:
	$(PYTHON) evals/benchmark.py --workers $(WORKERS) --max-packages $(BENIGN_PACKAGES) --ecosystems $(ECOSYSTEMS)

recall:
	$(PYTHON) evals/recall.py --workers $(WORKERS) --ecosystems $(ECOSYSTEMS) --no-sandbox

report:
	$(PYTHON) evals/run.py --phase report --threshold $(THRESHOLD) --ecosystems $(ECOSYSTEMS)

resample:
	$(PYTHON) evals/recall.py --regenerate-samples --samples-per-ecosystem $(SAMPLES_PER_ECO) --ecosystems $(ECOSYSTEMS)

clean:
	rm -rf evals/workdir/results evals/workdir/recall_results evals/workdir/*.html
