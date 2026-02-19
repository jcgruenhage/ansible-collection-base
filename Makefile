all: lock venv format lint

venv:
	uv sync --dev

lock:
	uv lock

format: ruff-format

lint: ruff-check

ruff-format:
	uv run ruff format

ruff-check:
	uv run ruff check
