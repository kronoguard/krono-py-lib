.PHONY: help install quality lint format typecheck test test-unit test-integration test-smoke test-e2e coverage clean

PY := uv run
SRC := src/krono
TESTS := tests

help:
	@echo "krono — make targets"
	@echo "  install         install package + dev extras via uv"
	@echo "  quality         ruff check + ruff format --check + mypy --strict"
	@echo "  lint            ruff check only"
	@echo "  format          ruff format (writes)"
	@echo "  typecheck       mypy --strict on $(SRC)"
	@echo "  test            pytest with coverage gate (statement + branch >= 97%)"
	@echo "  test-unit       pytest tests/ excluding integration"
	@echo "  test-integration pytest tests/integration"
	@echo "  test-smoke      pytest -m smoke"
	@echo "  test-e2e        pytest -m e2e"
	@echo "  coverage        pytest with coverage report (no gate)"
	@echo "  clean           remove caches and build artifacts"

install:
	uv sync --all-extras

quality: lint format-check typecheck

lint:
	$(PY) ruff check $(SRC) $(TESTS)

format:
	$(PY) ruff format $(SRC) $(TESTS)

format-check:
	$(PY) ruff format --check $(SRC) $(TESTS)

typecheck:
	$(PY) mypy --strict $(SRC)

test:
	$(PY) pytest $(TESTS) \
		--cov=$(SRC) \
		--cov-branch \
		--cov-report=term-missing \
		--cov-fail-under=97

test-unit:
	$(PY) pytest $(TESTS) --ignore=$(TESTS)/integration

test-integration:
	$(PY) pytest $(TESTS)/integration

test-smoke:
	$(PY) pytest -m smoke

test-e2e:
	$(PY) pytest -m e2e

coverage:
	$(PY) pytest $(TESTS) \
		--cov=$(SRC) \
		--cov-branch \
		--cov-report=term-missing \
		--cov-report=html

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
