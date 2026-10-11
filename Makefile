SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
export PATH := $(HOME)/.foundry/bin:$(PATH)

PY := .venv/bin/python

.PHONY: setup test eval-mock eval-live evidence ui

setup:
	if [ ! -d .venv ]; then uv venv --python 3.12 .venv; fi
	uv pip install --python .venv -e "agent[dev]"
	if [ -f .venv/Scripts/python.exe ] && [ ! -e .venv/bin/python ]; then \
		mkdir -p .venv/bin; \
		printf '%s\n' '#!/usr/bin/env bash' 'exec "$$(dirname "$$0")/../Scripts/python.exe" "$$@"' > .venv/bin/python; \
		chmod +x .venv/bin/python; \
	fi
	$(PY) -c "import sys, agentvax; print(sys.executable)"
	cd contracts && forge build

test:
	cd contracts && forge test
	$(PY) -m pytest agent/tests -q

eval-mock:
	$(PY) -m agentvax.eval.run --mode mock --out results

eval-live:
	$(PY) -m agentvax.eval.run --mode live --out results

evidence:
	$(PY) -m agentvax.evidence.run --network testnet

ui:
	$(PY) -m agentvax.api.app
