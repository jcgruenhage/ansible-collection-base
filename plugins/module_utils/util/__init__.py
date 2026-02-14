import traceback
from typing import Dict

MISSING_IMPORTS: Dict[str, str] = {}


def register_missing_import(name: str) -> None:
    """Record an optional dependency that failed to import, with its traceback."""
    MISSING_IMPORTS[name] = traceback.format_exc()
