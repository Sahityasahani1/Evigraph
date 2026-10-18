.PHONY: setup test lint format check help

PYTHON ?= python

help:
	@echo "Available Makefile targets:"
	@echo "  setup   Install pinned dependencies in editable mode"
	@echo "  test    Run pytest test suite"
	@echo "  lint    Run ruff linter check"
	@echo "  format  Run ruff code formatter"
	@echo "  check   Run lint and test"

setup:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/data

lint:
	$(PYTHON) -m ruff check evigraph tests/data

format:
	$(PYTHON) -m ruff format evigraph tests/data

check: lint test
