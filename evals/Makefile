ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))..
PYTHON ?= uv run --directory $(ROOT) python3
WORKERS ?= 20
BENIGN_PACKAGES ?= 1000
SAMPLES_PER_ECO ?= 1000
THRESHOLD ?= 5.0
ECOSYSTEMS ?= pypi npm
MAX_PER_CLUSTER ?= 3
DATASET_PATH ?=

.PHONY: all precision recall report resample cluster clean

all: precision recall report

precision:
	$(PYTHON) $(ROOT)/evals/benchmark.py --workers $(WORKERS) --max-packages $(BENIGN_PACKAGES) --ecosystems $(ECOSYSTEMS)

recall:
	$(PYTHON) $(ROOT)/evals/recall.py --workers $(WORKERS) --ecosystems $(ECOSYSTEMS) --no-sandbox

report:
	$(PYTHON) $(ROOT)/evals/run.py --phase report --threshold $(THRESHOLD) --ecosystems $(ECOSYSTEMS)

cluster:
	$(PYTHON) $(ROOT)/evals/cluster.py --ecosystems $(ECOSYSTEMS) --workers $(WORKERS) $(if $(DATASET_PATH),--dataset-path $(DATASET_PATH))

resample:
	$(PYTHON) $(ROOT)/evals/recall.py --regenerate-samples --samples-per-ecosystem $(SAMPLES_PER_ECO) --ecosystems $(ECOSYSTEMS) --max-per-cluster $(MAX_PER_CLUSTER)

clean:
	rm -rf $(ROOT)/evals/workdir/results $(ROOT)/evals/workdir/recall_results $(ROOT)/evals/workdir/*.html
