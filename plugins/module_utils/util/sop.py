# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""SOP executable resolution and single place for running the sop subprocess. Shared by config and SOP backend."""

import os
from typing import Dict, List, Optional
import shutil
import subprocess
from pathlib import Path


class SOPExecutableNotConfiguredError(Exception):
    """Raised when no SOP executable is provided (None or empty string)."""


class SOPExecutableNotFoundError(Exception):
    """Raised when an executable is configured but not findable (path missing or not in PATH)."""


def resolve_sop_executable(configured: Optional[Path]) -> Path:
    """Resolve SOP executable to an absolute path.

    Returns absolute Path to the executable.
    Raises SOPExecutableNotConfiguredError if not provided (None or empty).
    Raises SOPExecutableNotFoundError if provided but path/name not findable.
    """
    if configured is None or str(configured).strip() == "":
        raise SOPExecutableNotConfiguredError(
            "SOP executable must be provided via config: for encryption set sop.encryption.exec or sop.exec, "
            "for decryption set sop.decryption.exec or sop.exec; or use env ANSIBLE_OPENPGP_SECRETSTORE_SOP_EXEC / "
            "_SOP_ENCRYPTION_EXEC / _SOP_DECRYPTION_EXEC"
        )
    value = str(configured).strip()
    if os.path.sep in value or Path(value).expanduser().is_absolute():
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise SOPExecutableNotFoundError(
                "SOP executable not found at configured path: %s" % path
            )
        return path
    found = shutil.which(value)
    if not found:
        raise SOPExecutableNotFoundError(
            "SOP executable %r not found in PATH (check config or ANSIBLE_OPENPGP_SECRETSTORE_SOP_*_EXEC)"
            % value
        )
    return Path(found)


def run_sop(
    executable: Path,
    args: List[str],
    stdin: Optional[bytes] = None,
    env: Optional[Dict[str, str]] = None,
) -> bytes:
    """Run sop (or rsoct etc.) subprocess. Single mock point for tests.

    Args:
        executable: Absolute path to SOP binary (e.g. from resolve_sop_executable).
        args: Command-line arguments (e.g. ["decrypt", "/path/to/key"]).
        stdin: Optional stdin bytes (e.g. ciphertext).
        env: Optional environment for the subprocess.

    Returns:
        stdout bytes.
    """
    cmd = [str(executable)] + args
    result = subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "%s failed (exit %s): %s"
            % (
                str(executable),
                result.returncode,
                (result.stderr or b"").decode("utf-8", errors="replace"),
            )
        )
    return result.stdout
