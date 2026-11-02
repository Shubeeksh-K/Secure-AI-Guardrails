.PHONY: install lint format test check

install:
	uv sync --frozen

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check . --fix
	uv run ruff format .

test:
	uv run python -m pytest -q

check: lint test
