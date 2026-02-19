# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.util.gpg (run_gpg mocked to avoid requiring gpg binary)."""

import unittest
from unittest import mock

from ansible_collections.famedly.base.plugins.module_utils.util import gpg as gpg_module


class TestRunGpg(unittest.TestCase):
    def test_run_gpg_decrypt_returns_stdout(self):
        with mock.patch.object(
            gpg_module, "_find_gnupg_binary", return_value="/usr/bin/gpg"
        ):
            with mock.patch("subprocess.run") as subprocess_run:
                subprocess_run.return_value = mock.MagicMock(
                    returncode=0, stdout=b"plaintext", stderr=b""
                )
                result = gpg_module.run_gpg(
                    ["--decrypt", "--batch", "-"], stdin=b"cipher"
                )
        self.assertEqual(result, b"plaintext")
        subprocess_run.assert_called_once()
        call_args = subprocess_run.call_args[0][0]
        self.assertIn("--decrypt", call_args)

    def test_run_gpg_nonzero_exit_raises(self):
        with mock.patch.object(
            gpg_module, "_find_gnupg_binary", return_value="/usr/bin/gpg"
        ):
            with mock.patch("subprocess.run") as subprocess_run:
                subprocess_run.return_value = mock.MagicMock(
                    returncode=1, stdout=b"", stderr=b"decryption failed"
                )
                with self.assertRaises(RuntimeError) as ctx:
                    gpg_module.run_gpg(["--decrypt", "-"], stdin=b"x")
        self.assertIn("failed", str(ctx.exception))
