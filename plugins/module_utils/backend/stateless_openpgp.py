# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""SOP backend: uses validated config (resolved exec paths and key)."""

from typing import Any, List

from ..util.config import SecretStoreConfig, is_set
from ..util import pgp as pgp_util
from ..util.sop import run_sop


class SOPBackend:
    """SOP backend: separate encryption/decryption executables, cert store for encrypt, key path for decrypt."""

    def __init__(self, config: SecretStoreConfig, **params: Any) -> None:
        """Build from validated config. config.sop must be set (caller uses backend=sop only)."""
        if config.sop is None:
            raise ValueError("SOPBackend requires config.sop (backend=sop)")
        self._config = config

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using sop decrypt KEYS. Caller has already read the file.
        Note: --with-key-password passes the password on the CLI; it may be visible in process listings.
        """
        sop = self._config.sop
        if sop is None:
            raise AssertionError("SOP config validated in __init__")
        args = ["decrypt"]
        if is_set(sop.decryption.password):
            args.append(f"--with-key-password={sop.decryption.password}")
        args.append(str(sop.decryption.key_path))
        return run_sop(sop.decryption.exec, args, stdin=ciphertext)

    def encrypt(self, plaintext: bytes, recipient_fingerprints: List[str]) -> bytes:
        """Encrypt plaintext to the given recipients. Resolves each fingerprint to cert path in PGP cert-d."""
        sop = self._config.sop
        if sop is None:
            raise AssertionError("SOP config validated in __init__")
        cert_paths = []
        for fp in recipient_fingerprints:
            path = pgp_util.resolve_fingerprint_to_pgp_cert_d_path(
                self._config.pgp_cert_d_path, fp
            )
            cert_paths.append(str(path))
        args = ["encrypt", "--no-armor"] + cert_paths
        return run_sop(sop.encryption.exec, args, stdin=plaintext)
