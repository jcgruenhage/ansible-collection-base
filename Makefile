all: lock venv format lint test

venv:
	uv sync --dev

lock:
	uv lock

format: ruff-format

lint: ruff-check ty-check ansible-lint ansible-sanity

test: ansible-units ansible-integration

ruff-format:
	uv run ruff format

ruff-check:
	uv run ruff check

ty-check:
	uv run ty check

ansible-lint:
	uv run ansible-lint

ansible-sanity:
	uv sync --python 3.12 --dev
	uv run ansible-test sanity --python 3.12
	uv sync --python 3.13 --dev
	uv run ansible-test sanity --python 3.13
	uv sync --python 3.14 --dev
	uv run ansible-test sanity --python 3.14

ansible-units:
	uv sync --python 3.12 --dev
	uv run ansible-test units --python 3.12
	uv sync --python 3.13 --dev
	uv run ansible-test units --python 3.13
	uv sync --python 3.14 --dev
	uv run ansible-test units --python 3.14

ansible-integration:
	uv sync --python 3.12 --dev
	uv run ansible-test integration --python 3.12
	uv sync --python 3.13 --dev
	uv run ansible-test integration --python 3.13
	uv sync --python 3.14 --dev
	uv run ansible-test integration --python 3.14
