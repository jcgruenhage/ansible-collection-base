all: lock venv

venv:
	uv sync --dev

lock:
	uv lock
