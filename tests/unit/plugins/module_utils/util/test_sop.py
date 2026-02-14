# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.util.sop."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ansible_collections.famedly.base.plugins.module_utils.util.sop import (
    SOPExecutableNotConfiguredError,
    SOPExecutableNotFoundError,
    resolve_sop_executable,
    run_sop,
)

RSOP = "rsop"
RSOP_ABSOLUTE = f"/usr/bin/{RSOP}"
PATH_RSOP = Path(RSOP)
PATH_RSOP_ABSOLUTE = Path(RSOP_ABSOLUTE)


class TestResolveSopExecutable(unittest.TestCase):
    def test_none_raises_not_configured(self):
        with self.assertRaises(SOPExecutableNotConfiguredError):
            resolve_sop_executable(None)

    def test_whitespace_only_raises_not_configured(self):
        # Path("") stringifies to "."; use a value that strips to empty
        class EmptyStr:
            def __str__(self):
                return "   "

        with self.assertRaises(SOPExecutableNotConfiguredError):
            resolve_sop_executable(EmptyStr())  # type: ignore[invalid-argument-type]

    def test_absolute_path_to_existing_file_returns_path(self):
        with tempfile.NamedTemporaryFile(suffix="sop", delete=False) as f:
            path = Path(f.name)
        try:
            result = resolve_sop_executable(path)
            self.assertEqual(result, path.resolve())
        finally:
            path.unlink(missing_ok=True)

    def test_bare_name_uses_which(self):
        with mock.patch("shutil.which") as which:
            which.return_value = RSOP_ABSOLUTE
            result = resolve_sop_executable(PATH_RSOP)
        self.assertEqual(result, PATH_RSOP_ABSOLUTE)

    def test_bare_name_not_found_raises(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(SOPExecutableNotFoundError):
                resolve_sop_executable(Path("nonexistent_sop_binary_xyz"))


class TestRunSop(unittest.TestCase):
    def test_run_sop_returns_stdout(self):
        with mock.patch("subprocess.run") as subprocess_run:
            subprocess_run.return_value = mock.MagicMock(
                returncode=0, stdout=b"output", stderr=b""
            )
            result = run_sop(PATH_RSOP_ABSOLUTE, ["version"], stdin=None)
        self.assertEqual(result, b"output")

    def test_run_sop_nonzero_exit_raises(self):
        with mock.patch("subprocess.run") as subprocess_run:
            subprocess_run.return_value = mock.MagicMock(
                returncode=1, stdout=b"", stderr=b"error"
            )
            with self.assertRaises(RuntimeError):
                run_sop(PATH_RSOP_ABSOLUTE, ["decrypt", "/key"], stdin=b"x")
