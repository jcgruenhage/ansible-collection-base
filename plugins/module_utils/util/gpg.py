# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Single place for running the gpg subprocess. Used by backend/gnupg and util/pgp (sync_gnupg_to_pgp_cert_d)."""

import re
from typing import List, Optional
import shutil
import subprocess


def _find_gnupg_binary() -> str:
    """Return path to GnuPG binary (prefer gpg2, then gpg). Validates 2.2.x or 2.4.x. Raises RuntimeError if not found or unsupported."""
    gpg = shutil.which("gpg2") or shutil.which("gpg")
    if gpg is None:
        raise RuntimeError("Could not find 'gpg2' or 'gpg' binary in PATH")
    _validate_gnupg_version(gpg)
    return gpg


def _validate_gnupg_version(gpg: str) -> None:
    """Ensure gpg is GnuPG 2.2 or 2.4. Raises RuntimeError if not supported or version unreadable."""
    result = subprocess.run(
        [gpg, "--list-config", "--with-colons"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Could not get GnuPG version (exit %s): %s"
            % (
                result.returncode,
                (result.stderr or b"").decode("utf-8", errors="replace"),
            )
        )
    text = result.stdout.decode("utf-8", errors="replace")
    m = re.search(r"cfg:version:(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)", text)
    if not m:
        raise RuntimeError("Could not find cfg:version in gpg --list-config output")
    major, minor, patch = m["major"], m["minor"], m["patch"]
    if major != "2" or minor not in ("2", "4"):
        raise RuntimeError(
            "Unsupported GnuPG version %s.%s.%s (supported: 2.2.x, 2.4.x)"
            % (major, minor, patch)
        )


def run_gpg(args: List[str], stdin: Optional[bytes] = None) -> bytes:
    """Run gpg subprocess; resolve gpg vs gpg2. Single mock point for tests.

    Args:
        args: Command-line arguments (e.g. ["--decrypt", "--batch", "-"]).
        stdin: Optional stdin bytes (e.g. ciphertext).

    Returns:
        stdout bytes.
    """
    gpg = _find_gnupg_binary()
    cmd = [gpg] + args
    result = subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "gpg failed (exit %s): %s"
            % (
                result.returncode,
                (result.stderr or b"").decode("utf-8", errors="replace"),
            )
        )
    return result.stdout
