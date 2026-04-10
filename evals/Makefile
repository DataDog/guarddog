ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..
PYTHON ?= uv run --directory $(ROOT) python3
WORKERS ?= 10
BENIGN_PACKAGES ?= 1000
SAMPLES_PER_ECO ?= 250
THRESHOLD ?= 5.0
ECOSYSTEMS ?= pypi npm

.PHONY: all precision recall report resample clean

all: precision recall report

precision:
	$(PYTHON) $(ROOT)/evals/benchmark.py --workers $(WORKERS) --max-packages $(BENIGN_PACKAGES) --ecosystems $(ECOSYSTEMS)

recall:
	$(PYTHON) $(ROOT)/evals/recall.py --workers $(WORKERS) --ecosystems $(ECOSYSTEMS) --no-sandbox

report:
	$(PYTHON) $(ROOT)/evals/run.py --phase report --threshold $(THRESHOLD) --ecosystems $(ECOSYSTEMS)

resample:
	$(PYTHON) $(ROOT)/evals/recall.py --regenerate-samples --samples-per-ecosystem $(SAMPLES_PER_ECO) --ecosystems $(ECOSYSTEMS)

clean:
	rm -rf $(ROOT)/evals/workdir/results $(ROOT)/evals/workdir/recall_results $(ROOT)/evals/workdir/*.html
