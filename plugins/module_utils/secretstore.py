# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""High-level secret store: SecretStore with backend delegation and config loading."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Protocol, Tuple

from .util import register_missing_import

if TYPE_CHECKING:
    import yaml
    from filelock import FileLock
    from git import InvalidGitRepositoryError, Repo
else:
    try:
        import yaml
    except ImportError:
        register_missing_import("PyYAML")
    try:
        from filelock import FileLock
    except ImportError:
        register_missing_import("filelock")
    try:
        from git import InvalidGitRepositoryError, Repo
    except ImportError:
        register_missing_import("GitPython")

from .util.config import (
    load_secretstore_config,
    SecretStoreConfig,
)
from .util.generate import DataTypeLiteral, SecretData, SecretGenerator
from .util import pgp as pgp_util
from .backend.gnupg import GnuPGBackend
from .backend.stateless_openpgp import SOPBackend


StateLiteral = Literal["present", "absent"]
ActionLiteral = Literal["generate", "delete", "regenerate", "reencrypt"]


class RecipientsMismatchError(Exception):
    """Raised when ciphertext recipients do not match .gpg-id."""


# Backend protocol: only decrypt/encrypt; file I/O stays in SecretStore.


class BackendProtocol(Protocol):
    """Backend for encrypt/decrypt. Implemented by GnuPGBackend and SOPBackend."""

    def decrypt(self, ciphertext: bytes) -> bytes: ...

    def encrypt(self, plaintext: bytes, recipient_fingerprints: List[str]) -> bytes: ...


def build_backend(config: SecretStoreConfig) -> BackendProtocol:
    """Build the backend instance for the validated config."""
    if config.backend == "gnupg":
        return GnuPGBackend()
    if config.backend == "sop":
        return SOPBackend(config)
    raise AssertionError("unreachable: backend validated")


def _data_to_plaintext(
    data: SecretData,
    data_type: DataTypeLiteral,
    encoding: str = "UTF-8",
) -> bytes:
    if data_type == "plain":
        return (data if isinstance(data, str) else str(data)).encode(encoding)
    if data_type == "json":
        return json.dumps(data, ensure_ascii=False).encode(encoding)
    if data_type == "yaml":
        return yaml.dump(data, allow_unicode=True, default_flow_style=False).encode(
            encoding
        )


def _commit_changes(repo_path: str, file_path: str, action: ActionLiteral) -> None:
    """Commit change in the password store git repo. Skips if not a git repo. Uses a per-repo lock."""
    lock_path = Path("/tmp") / hashlib.sha256(repo_path.encode()).hexdigest()
    with FileLock(lock_path.as_posix()):
        try:
            repo = Repo(repo_path)
        except InvalidGitRepositoryError:
            return
        if action == "delete":
            repo.index.remove(file_path)
            message = "Deleted secret %s" % file_path
        else:
            repo.index.add(file_path)
            messages: Dict[ActionLiteral, str] = {
                "generate": "Generated secret %s",
                "regenerate": "Regenerated secret %s",
                "reencrypt": "Reencrypted secret %s",
            }
            message = messages[action] % file_path
        repo.index.write()
        repo.git.commit("-m", message)


def _plaintext_to_data(
    raw: bytes,
    data_type: DataTypeLiteral,
    encoding: str = "UTF-8",
) -> SecretData:
    text = raw.decode(encoding)
    if data_type == "plain":
        return text
    if data_type == "json":
        return json.loads(text)
    if data_type == "yaml":
        return yaml.safe_load(text)


@dataclass
class GetResult:
    """Result of SecretStore.get(): the secret data plus whether it was newly added or re-encrypted."""

    data: SecretData
    added: bool  # True if file was missing and we generated and saved
    re_encrypted: bool  # True if we re-encrypted for recipient mismatch
    diff_before: List[str]
    diff_after: List[str]


@dataclass
class EnsureResult:
    """Result of SecretStore.ensure(): state machine outcome for present/absent, overwrite, check_mode."""

    changed: bool
    action: Optional[ActionLiteral]
    secret: Optional[SecretData]
    diff_before: List[str]
    diff_after: List[str]
    message: str
    warning: List[str]


# Pass compatibility: fixed names
class SecretStore:
    """High-level secret store: path resolution, file I/O, delegates encrypt/decrypt to backend.
    Pass-compatible: FILE_EXTENSION and RECIPIENTS_LIST_FILE are fixed. pgp_cert_d_path from config/env only.
    get() generates and saves using _generate if the secret file is absent. Default generator: random/plain.
    """

    ENCODING: str = "UTF-8"
    FILE_EXTENSION: str = ".gpg"
    RECIPIENTS_LIST_FILE: str = ".gpg-id"

    password_store_path: Path
    _backend: BackendProtocol
    pgp_cert_d_path: Path
    _generate: SecretGenerator

    def __init__(
        self,
        password_store_path: Optional[Path] = None,
        generate: Optional[SecretGenerator] = None,
        config_path: Optional[Path] = None,
    ):
        config = load_secretstore_config(password_store_path=password_store_path, config_path=config_path)
        self._backend = build_backend(config)
        self.pgp_cert_d_path = config.pgp_cert_d_path
        self.password_store_path = config.password_store_path
        self._generate = generate if generate is not None else SecretGenerator()

    def _path_for_slug(self, slug: str) -> Path:
        return self.password_store_path / (slug + self.FILE_EXTENSION)

    def _load(self, path: Path, slug: str) -> Tuple[SecretData, List[str]]:
        """Read path, decrypt, decode; return (decoded_value, recipient_key_ids from ciphertext)."""
        ciphertext = path.read_bytes()
        recipient_ids = pgp_util.get_recipient_key_ids(ciphertext)
        raw = self._backend.decrypt(ciphertext)
        decoded = _plaintext_to_data(raw, self._generate.data_type, self.ENCODING)
        return (decoded, recipient_ids)

    def _save(
        self,
        path: Path,
        slug: str,
        data: SecretData,
        recipients: List[str],
        check_mode: bool = False,
    ) -> List[str]:
        """Encode, encrypt, optionally write to path; return recipient_key_ids from the ciphertext.
        When check_mode is True, do not write to disk."""
        plaintext = _data_to_plaintext(data, self._generate.data_type, self.ENCODING)
        ciphertext = self._backend.encrypt(plaintext, recipients)
        recipient_ids = pgp_util.get_recipient_key_ids(ciphertext)
        if not check_mode:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(ciphertext)
        return recipient_ids

    def remove(self, slug: str) -> None:
        """Remove the encrypted secret file for the given slug."""
        path = self._path_for_slug(slug)
        if path.exists():
            path.unlink()

    def get_recipients(self, slug: str) -> List[str]:
        """Read recipients list file for slug (pass semantics: walk up from slug dir). Return list of recipient IDs."""
        path = self._path_for_slug(slug)
        for directory in [
            d for d in path.parents if d not in self.password_store_path.parents
        ]:
            list_file = directory / self.RECIPIENTS_LIST_FILE
            if list_file.is_file():
                with list_file.open("r", encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                return lines
        raise FileNotFoundError(
            "No %s found in tree for %s" % (self.RECIPIENTS_LIST_FILE, slug)
        )

    def recipients_mismatch(self, actual_recipient_ids: List[str], slug: str) -> bool:
        """True if actual recipient key IDs do not match .gpg-id. No I/O beyond get_recipients(slug)."""
        wanted = self.get_recipients(slug)
        diff = pgp_util.diff_recipients(
            actual_recipient_ids, wanted, self.pgp_cert_d_path
        )
        return not diff["matched"]

    def get(
        self,
        slug: str,
        check_recipients: bool = True,
        check_mode: bool = False,
    ) -> GetResult:
        """Load and decrypt secret; if missing, generate and save (unless check_mode).
        Returns GetResult with data, added (new secret), re_encrypted (recipients fixed), and diff.
        """
        path = self._path_for_slug(slug)

        if not path.exists():
            data = self._generate.get_data()
            recipients = self.get_recipients(slug)
            after_ids = self._save(path, slug, data, recipients, check_mode=check_mode)
            return GetResult(
                data=data,
                added=True,
                re_encrypted=False,
                diff_before=[],
                diff_after=after_ids,
            )

        decoded, before_ids = self._load(path, slug)
        re_encrypted = False
        after_ids: List[str] = []
        if check_recipients and self.recipients_mismatch(before_ids, slug):
            recipients = self.get_recipients(slug)
            after_ids = self._save(
                path, slug, decoded, recipients, check_mode=check_mode
            )
            re_encrypted = True

        return GetResult(
            data=decoded,
            added=False,
            re_encrypted=re_encrypted,
            diff_before=before_ids if re_encrypted else [],
            diff_after=after_ids,
        )

    def ensure(
        self,
        slug: str,
        state: StateLiteral = "present",
        overwrite: bool = False,
        check_mode: bool = False,
        check_recipients: bool = True,
        commit_changes: bool = False,
    ) -> EnsureResult:
        """Ensure secret is present or absent. Respects overwrite and check_mode (no writes when check_mode).
        When commit_changes is True, holds a per-slug lock and runs git commit on change (requires filelock, GitPython).
        """
        path = self._path_for_slug(slug)
        warning: List[str] = []

        def _run() -> EnsureResult:
            if state == "absent":
                return self._ensure_absent(path, slug, check_mode, warning)
            return self._ensure_present(
                path, slug, overwrite, check_mode, check_recipients, warning
            )

        if not commit_changes:
            return _run()

        lock_path = Path("/tmp") / hashlib.sha256(slug.encode()).hexdigest()
        with FileLock(lock_path.as_posix()):
            er = _run()
            if er.changed and not check_mode and er.action is not None:
                _commit_changes(
                    str(self.password_store_path),
                    slug + self.FILE_EXTENSION,
                    er.action,
                )
            return er

    def _ensure_absent(
        self, path: Path, slug: str, check_mode: bool, warning: List[str]
    ) -> EnsureResult:
        """Handle state=absent: remove file if present."""
        if not path.exists():
            return EnsureResult(
                changed=False,
                action=None,
                secret=None,
                diff_before=[],
                diff_after=[],
                message="Secret did not exist.",
                warning=warning,
            )
        try:
            diff_before = self._load(path, slug)[1]
        except (FileNotFoundError, RuntimeError):
            diff_before = []
        if not check_mode:
            self.remove(slug)
        return EnsureResult(
            changed=True,
            action="delete",
            secret=None,
            diff_before=diff_before,
            diff_after=[],
            message="Secret removed.",
            warning=warning,
        )

    def _ensure_present(
        self,
        path: Path,
        slug: str,
        overwrite: bool,
        check_mode: bool,
        check_recipients: bool,
        warning: List[str],
    ) -> EnsureResult:
        """Handle state=present: get or generate secret, optionally overwriting."""
        removed_for_overwrite = False
        # Overwrite: remove first so get() will generate (or report would-rotate in check_mode).
        if overwrite and path.exists():
            if check_mode:
                from .util.generate import UserSuppliedSecretMissingError

                try:
                    secret = self._generate.get_data()
                    recipients = self.get_recipients(slug)
                    after_ids = self._save(
                        path, slug, secret, recipients, check_mode=check_mode
                    )
                except UserSuppliedSecretMissingError as e:
                    raise ValueError(str(e)) from e
                return EnsureResult(
                    changed=True,
                    action="regenerate",
                    secret=secret,
                    diff_before=[],
                    diff_after=after_ids,
                    message="Secret rotation requested: rotating.",
                    warning=warning,
                )
            self.remove(slug)
            removed_for_overwrite = True

        result = self.get(
            slug, check_recipients=check_recipients, check_mode=check_mode
        )

        if result.added:
            action: ActionLiteral = (
                "regenerate" if removed_for_overwrite else "generate"
            )
            return EnsureResult(
                changed=True,
                action=action,
                secret=result.data,
                diff_before=result.diff_before,
                diff_after=result.diff_after,
                message="Secret not found; generated new secret.",
                warning=warning,
            )
        if result.re_encrypted:
            warning.append("Secret recipient mismatch; re-encrypting.")
            return EnsureResult(
                changed=True,
                action="reencrypt",
                secret=result.data,
                diff_before=result.diff_before,
                diff_after=result.diff_after,
                message="Re-encrypted for recipient match.",
                warning=warning,
            )
        return EnsureResult(
            changed=False,
            action=None,
            secret=result.data,
            diff_before=[],
            diff_after=[],
            message="",
            warning=warning,
        )
