# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""GnuPG backend: subprocess gpg, default keyring. No python-gnupg."""

from typing import List

from ..util.gpg import run_gpg


class GnuPGBackend:
    """GnuPG backend: subprocess gpg for encrypt/decrypt. Uses default GnuPG keyring (no keyring path)."""

    def __init__(self) -> None:
        """Uses default GnuPG keyring (no keyring path)."""

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext; caller has already read the file. Returns plaintext bytes."""
        args = ["--decrypt", "--batch", "-"]
        return run_gpg(args, stdin=ciphertext)

    def encrypt(self, plaintext: bytes, recipient_fingerprints: List[str]) -> bytes:
        """Encrypt plaintext to the given recipient fingerprints. GnuPG resolves keys from default keyring.
        Output is binary (no armor) for pass compatibility.
        """
        args = ["--encrypt", "--batch", "--no-armor", "-o", "-"]
        for fp in recipient_fingerprints:
            args.extend(["-r", fp])
        args.append("-")
        return run_gpg(args, stdin=plaintext)
