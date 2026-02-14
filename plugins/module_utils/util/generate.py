# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Secret generation for secret store: random, binary command, or user-supplied."""

import json
import re
import secrets
import string
import subprocess
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Tuple, Union

from . import register_missing_import

if TYPE_CHECKING:
    import yaml
else:
    try:
        import yaml
    except ImportError:
        register_missing_import("PyYAML")

SecretTypeLiteral = Literal["random", "binary", "user_supplied"]
DataTypeLiteral = Literal["plain", "json", "yaml"]
ALLOWED_SECRET_TYPES: Tuple[SecretTypeLiteral, ...] = (
    "random",
    "binary",
    "user_supplied",
)
# Decoded secret: plain string, or JSON/YAML structure.
SecretData = Union[str, Dict[str, Any], List[Any]]


class UserSuppliedSecretMissingError(Exception):
    """Raised when secret_type is user_supplied but no value was provided."""


def _random_secret(
    length: int = 30,
    letter_pattern: str = "([a-zA-Z0-9])",
) -> str:
    characters = re.findall(letter_pattern, string.printable)
    if not characters:
        raise ValueError("letter_pattern must match at least one character")
    return "".join(secrets.choice(characters) for _unused in range(length))


def _binary_secret(binary: Optional[str]) -> str:
    if binary is None:
        raise ValueError("secret_type=binary requires binary")
    result = subprocess.run(
        ["sh", "-c", binary],
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout


def _user_supplied_secret(user_supplied_secret: Optional[str]) -> str:
    if user_supplied_secret is None:
        raise UserSuppliedSecretMissingError(
            "User supplied secret configured, but it's neither in the store nor supplied"
        )
    return user_supplied_secret


def _decode_raw(raw: str, data_type: DataTypeLiteral) -> SecretData:
    if data_type == "plain":
        return raw
    if data_type == "json":
        return json.loads(raw)
    if data_type == "yaml":
        return yaml.safe_load(raw)
    raise ValueError(f"data_type must be plain, json, or yaml, got {data_type!r}")


class SecretGenerator:
    """Typed options for generating a secret when the store entry is missing. Pass to SecretStore(generate=...)."""

    def __init__(
        self,
        secret_type: SecretTypeLiteral = "random",
        data_type: DataTypeLiteral = "plain",
        *,
        length: int = 30,
        letter_pattern: str = "([A-Za-z0-9])",
        binary: Optional[str] = None,
        user_supplied_secret: Optional[str] = None,
    ):
        if secret_type not in ALLOWED_SECRET_TYPES:
            raise ValueError(
                f"secret_type must be one of {ALLOWED_SECRET_TYPES}, got {secret_type!r}"
            )
        if data_type not in ("plain", "json", "yaml"):
            raise ValueError("data_type must be plain, json, or yaml")
        self.secret_type = secret_type
        self.data_type = data_type
        self.length = length
        self.letter_pattern = letter_pattern
        self.binary = binary
        self.user_supplied_secret = user_supplied_secret

    def get_data(self) -> SecretData:
        """Generate and return secret data decoded per self.data_type."""
        if self.secret_type == "random":
            raw = _random_secret(length=self.length, letter_pattern=self.letter_pattern)
        elif self.secret_type == "binary":
            raw = _binary_secret(self.binary)
        else:
            raw = _user_supplied_secret(self.user_supplied_secret)
        return _decode_raw(raw, self.data_type)
