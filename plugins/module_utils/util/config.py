# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Config: raw load (YAML + env), validation (resolve backend + paths), and resolved SecretStoreConfig."""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional, Tuple, Union, cast

from . import register_missing_import

if TYPE_CHECKING:
    from dataclass_wizard import YAMLWizard
else:
    try:
        from dataclass_wizard import YAMLWizard
    except ImportError:
        YAMLWizard = object
        register_missing_import("dataclass-wizard")

__all__ = [
    "BackendLiteral",
    "SecretStoreConfig",
    "SOPConfig",
    "SOPEncryptionConfig",
    "SOPDecryptionConfig",
    "is_set",
    "load_secretstore_config",
]

_CONFIG_DIR_NAME = "ansible-openpgp-secretstore"
_CONFIG_FILENAME = "config.yaml"

BackendLiteral = Literal["gnupg", "sop"]
_VALID_BACKENDS: Tuple[BackendLiteral, ...] = ("gnupg", "sop")

_DEFAULT_PASSWORD_STORE_PATH = Path("~/.password-store/")


def _get_config_file_path() -> Path:
    """Return path to config.yaml for the current platform.

    Linux: $XDG_CONFIG_HOME/ansible-openpgp-secretstore or $HOME/.config/...
    macOS: $HOME/Library/Application Support/ansible-openpgp-secretstore
    Windows: %APPDATA%\\ansible-openpgp-secretstore\\config.yaml
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "") or os.path.expanduser("~")
        base = Path(appdata) / _CONFIG_DIR_NAME
    elif sys.platform == "darwin":
        home = os.environ.get("HOME", os.path.expanduser("~"))
        base = Path(home) / "Library" / "Application Support" / _CONFIG_DIR_NAME
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        if xdg:
            base = Path(xdg) / _CONFIG_DIR_NAME
        else:
            home = os.environ.get("HOME", os.path.expanduser("~"))
            base = Path(home) / ".config" / _CONFIG_DIR_NAME
    return base / _CONFIG_FILENAME


def _get_default_pgp_cert_d_path() -> Path:
    """Return default PGP cert store path for the current platform (PGP cert-d §3.1, 3.8).

    No env lookup here. POSIX: $XDG_DATA_HOME/pgp.cert.d (default $HOME/.local/share),
    macOS: $HOME/Library/Application Support/pgp.cert.d,
    Windows: %APPDATA%/pgp.cert.d (fallback Path.home()/AppData/Roaming if APPDATA unset).
    PGP_CERT_D is applied in apply_overrides_from_env.
    """
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA")
        if appdata:
            return Path(appdata) / "pgp.cert.d"
        return Path.home() / "AppData" / "Roaming" / "pgp.cert.d"
    if sys.platform == "darwin":
        home = os.environ.get("HOME", os.path.expanduser("~"))
        return Path(home) / "Library" / "Application Support" / "pgp.cert.d"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return Path(xdg) / "pgp.cert.d"
    home = os.environ.get("HOME", os.path.expanduser("~"))
    return Path(home) / ".local" / "share" / "pgp.cert.d"


@dataclass
class _RawSOPEncryptionConfig:
    """Raw SOP encryption: exec binary only."""

    exec: Optional[Path] = None

    def apply_overrides_from_env(self, prefix: str) -> None:
        exec = os.environ.get(prefix + "_EXEC")
        if exec is not None:
            self.exec = Path(exec)


@dataclass
class _RawSOPDecryptionConfig:
    """Raw SOP decryption: exec binary, key path, optional password."""

    exec: Optional[Path] = None
    key: Optional[Path] = None
    password: Optional[str] = None

    def apply_overrides_from_env(self, prefix: str) -> None:
        exec = os.environ.get(prefix + "_EXEC")
        if exec is not None:
            self.exec = Path(exec)
        key = os.environ.get(prefix + "_KEY")
        if key is not None:
            self.key = Path(key)
        password = os.environ.get(prefix + "_PASSWORD")
        if password is not None:
            self.password = password


@dataclass
class _RawSOPConfig:
    """Raw SOP: default exec and optional encryption/decryption overrides."""

    exec: Optional[Path] = None
    encryption: _RawSOPEncryptionConfig = field(default_factory=_RawSOPEncryptionConfig)
    decryption: _RawSOPDecryptionConfig = field(default_factory=_RawSOPDecryptionConfig)

    def apply_overrides_from_env(self, prefix: str) -> None:
        exec = os.environ.get(prefix + "_EXEC")
        if exec is not None:
            self.exec = Path(exec)
        self.encryption.apply_overrides_from_env(prefix + "_ENCRYPTION")
        self.decryption.apply_overrides_from_env(prefix + "_DECRYPTION")


def is_set(value: Optional[Union[Path, str]]) -> bool:
    """Return True if value is not None and has non-empty content after stripping."""
    return value is not None and str(value).strip() != ""


@dataclass
class _RawSecretStoreConfig(YAMLWizard):
    """Raw config: backend, password_store_path, pgp_cert_d, nested sop. Load from YAML; no coherence checks."""

    backend: Optional[BackendLiteral] = None
    password_store_path: Optional[Path] = None
    pgp_cert_d: Path = field(default_factory=_get_default_pgp_cert_d_path)
    sop: _RawSOPConfig = field(default_factory=_RawSOPConfig)

    def apply_overrides_from_env(
        self, prefix: str = "ANSIBLE_OPENPGP_SECRETSTORE"
    ) -> None:
        backend = os.environ.get(prefix + "_BACKEND")
        if backend is not None:
            if backend not in _VALID_BACKENDS:
                raise ValueError(
                    f"Invalid {prefix}_BACKEND={backend!r}; must be one of: {', '.join(_VALID_BACKENDS)}"
                )
            self.backend = cast(BackendLiteral, backend)
        password_store_path = os.environ.get(prefix + "_PASSWORD_STORE_PATH")
        if password_store_path is not None:
            self.password_store_path = Path(password_store_path)
        pgp_cert_d = os.environ.get("PGP_CERT_D") or os.environ.get(
            prefix + "_PGP_CERT_D"
        )
        if pgp_cert_d is not None:
            self.pgp_cert_d = Path(pgp_cert_d)
        self.sop.apply_overrides_from_env(prefix + "_SOP")

    def sop_intent(self) -> bool:
        """True if user expressed intent to use SOP (backend=sop or any sop option set)."""
        if self.backend == "sop":
            return True
        s = self.sop
        if is_set(s.decryption.key):
            return True
        enc_exec = s.encryption.exec or s.exec
        dec_exec = s.decryption.exec or s.exec
        if is_set(enc_exec) or is_set(dec_exec):
            return True
        return False

    def validate_backend(self) -> None:
        """Raise if self.backend is set and not in _VALID_BACKENDS."""
        if self.backend is not None and self.backend not in _VALID_BACKENDS:
            raise ValueError(
                "Invalid backend %r; must be one of: %s"
                % (self.backend, ", ".join(_VALID_BACKENDS))
            )

    def resolve_password_store_path(self, password_store_path: Optional[Path]) -> Path:
        """Resolve password store path: parameter > config > default."""
        if password_store_path is not None:
            return Path(password_store_path).expanduser().resolve()
        if self.password_store_path is not None:
            return Path(self.password_store_path).expanduser().resolve()
        return _DEFAULT_PASSWORD_STORE_PATH.expanduser().resolve()

    def resolve_pgp_cert_d_path(self) -> Path:
        """Resolve pgp_cert_d to absolute path."""
        return self.pgp_cert_d.resolve()

    def validate_sop_requirements(
        self,
    ) -> Tuple[Path, Path, Path, Optional[str]]:
        """Validate SOP config (decryption key + executables); return (enc_exec, dec_exec, key_path, password). Raises if missing."""
        from .sop import SOPExecutableNotConfiguredError, resolve_sop_executable

        if not is_set(self.sop.decryption.key):
            raise ValueError(
                "SOP backend requires sop.decryption.key (config or ANSIBLE_OPENPGP_SECRETSTORE_SOP_DECRYPTION_KEY)"
            )
        try:
            enc_exec = resolve_sop_executable(self.sop.encryption.exec or self.sop.exec)
            dec_exec = resolve_sop_executable(self.sop.decryption.exec or self.sop.exec)
        except SOPExecutableNotConfiguredError as e:
            raise ValueError(
                "SOP backend requires encryption and decryption executables "
                "(sop.encryption.exec / sop.decryption.exec or sop.exec, or env _SOP_*_EXEC). %s"
                % e
            ) from e
        key_path = (
            cast(Path, self.sop.decryption.key).expanduser().resolve()
        )  # validated by is_set above
        password = self.sop.decryption.password
        return (enc_exec, dec_exec, key_path, password)


@dataclass
class SOPEncryptionConfig:
    """Resolved SOP encryption: exec path only (absolute Path)."""

    exec: Path


@dataclass
class SOPDecryptionConfig:
    """Resolved SOP decryption: exec path (absolute Path), key path, optional password."""

    exec: Path
    key_path: Path
    password: Optional[str]


@dataclass
class SOPConfig:
    """Resolved SOP config: encryption and decryption sub-configs. Used when backend is sop."""

    encryption: SOPEncryptionConfig
    decryption: SOPDecryptionConfig


@dataclass
class SecretStoreConfig:
    """Validated config: backend and paths resolved; SOP fully specified when backend is sop."""

    backend: BackendLiteral
    password_store_path: Path
    pgp_cert_d_path: Path
    sop: Optional[SOPConfig] = None  # set when backend is sop


def _build_gnupg_config(
    password_store_path: Path,
    pgp_cert_d_path: Path,
) -> SecretStoreConfig:
    """Build validated config for backend=gnupg."""
    return SecretStoreConfig(
        backend="gnupg",
        password_store_path=password_store_path,
        pgp_cert_d_path=pgp_cert_d_path,
        sop=None,
    )


def _build_sop_config(
    enc_exec: Path,
    dec_exec: Path,
    key_path: Path,
    password: Optional[str],
) -> SOPConfig:
    """Build resolved SOPConfig from validated exec paths and key."""
    return SOPConfig(
        encryption=SOPEncryptionConfig(exec=enc_exec),
        decryption=SOPDecryptionConfig(
            exec=dec_exec,
            key_path=key_path,
            password=password,
        ),
    )


def _build_sop_secretstore_config(
    password_store_path: Path,
    pgp_cert_d_path: Path,
    sop_config: SOPConfig,
) -> SecretStoreConfig:
    """Build validated SecretStoreConfig for backend=sop."""
    return SecretStoreConfig(
        backend="sop",
        password_store_path=password_store_path,
        pgp_cert_d_path=pgp_cert_d_path,
        sop=sop_config,
    )


def _validate_secretstore_config(
    raw: _RawSecretStoreConfig,
    password_store_path: Optional[Path],
) -> SecretStoreConfig:
    """Convert raw config to validated config. Raises if config is incoherent (e.g. sop intent but incomplete)."""
    raw.validate_backend()
    resolved_store = raw.resolve_password_store_path(password_store_path)
    pgp_cert_d_path = raw.resolve_pgp_cert_d_path()

    # Explicit backend wins; only infer from intent when backend is not set.
    backend, sop_intent = (
        raw.backend,
        (raw.sop_intent() if raw.backend is None else None),
    )
    if backend == "gnupg" or (backend is None and sop_intent is False):
        return _build_gnupg_config(resolved_store, pgp_cert_d_path)
    if backend == "sop" or (backend is None and sop_intent is True):
        sop_config = _build_sop_config(*raw.validate_sop_requirements())
        return _build_sop_secretstore_config(
            resolved_store, pgp_cert_d_path, sop_config
        )
    raise AssertionError("unreachable: backend validated and cases exhaustive")


def load_secretstore_config(
    password_store_path: Optional[Path] = None,
    config_path: Optional[Path] = None,
) -> SecretStoreConfig:
    """Load YAML and env into raw config, validate, and return resolved SecretStoreConfig.

    C(password_store_path) overrides config/file; otherwise config value or default ~/.password-store/ is used.
    C(config_path) overrides default config file location; if provided, that path is used instead of platform default.
    Raises on malformed YAML or incoherent config (e.g. backend=sop with missing key or executables).
    """
    path = Path(config_path) if config_path is not None else _get_config_file_path()
    if not path.is_file():
        raw = _RawSecretStoreConfig()
        raw.apply_overrides_from_env()
    else:
        raw = _RawSecretStoreConfig.from_yaml_file(path)
        if isinstance(raw, list):
            raw = raw[0]
        if not isinstance(raw, _RawSecretStoreConfig):
            raise ValueError(f"Invalid config file {path}: {raw}")
        raw.apply_overrides_from_env()
    return _validate_secretstore_config(raw, password_store_path)
