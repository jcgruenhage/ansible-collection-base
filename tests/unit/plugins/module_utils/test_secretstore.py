# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.secretstore."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ansible_collections.famedly.base.plugins.module_utils.backend.gnupg import (
    GnuPGBackend,
)
from ansible_collections.famedly.base.plugins.module_utils.backend.stateless_openpgp import (
    SOPBackend,
)
from ansible_collections.famedly.base.plugins.module_utils.secretstore import (
    build_backend,
    SecretStore,
)
from ansible_collections.famedly.base.plugins.module_utils.util.config import (
    SecretStoreConfig,
    SOPConfig,
    SOPDecryptionConfig,
    SOPEncryptionConfig,
)
from ansible_collections.famedly.base.plugins.module_utils.util.generate import (
    SecretGenerator,
)


def _gnupg_config(store_path: Path) -> SecretStoreConfig:
    return SecretStoreConfig(
        backend="gnupg",
        password_store_path=store_path,
        pgp_cert_d_path=store_path,
        sop=None,
    )


def _sop_config(store_path: Path) -> SecretStoreConfig:
    return SecretStoreConfig(
        backend="sop",
        password_store_path=store_path,
        pgp_cert_d_path=store_path,
        sop=SOPConfig(
            encryption=SOPEncryptionConfig(exec=Path("/usr/bin/rsop")),
            decryption=SOPDecryptionConfig(
                exec=Path("/usr/bin/rsop"),
                key_path=Path("/tmp/key.asc").resolve(),
                password=None,
            ),
        ),
    )


class TestBuildBackend(unittest.TestCase):
    def test_gnupg_returns_gnupg_backend(self):
        config = _gnupg_config(Path("/tmp"))
        backend = build_backend(config)
        self.assertIsInstance(backend, GnuPGBackend)

    def test_sop_returns_sop_backend(self):
        config = _sop_config(Path("/tmp"))
        backend = build_backend(config)
        self.assertIsInstance(backend, SOPBackend)

    def test_invalid_backend_raises(self):
        config = _gnupg_config(Path("/tmp"))
        object.__setattr__(config, "backend", "invalid")
        with self.assertRaises(AssertionError):
            build_backend(config)


class TestSecretStoreGetRecipients(unittest.TestCase):
    def test_get_recipients_reads_gpg_id(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = Path(d)
            (store_path / ".gpg-id").write_text("deadbeef01234567\n")
            config = _gnupg_config(store_path)
            with (
                mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.secretstore.load_secretstore_config",
                    return_value=config,
                ),
                mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.secretstore.build_backend"
                ) as build,
            ):
                mock_backend = mock.MagicMock()
                build.return_value = mock_backend
                store = SecretStore(
                    password_store_path=store_path,
                    generate=SecretGenerator(),
                )
                recipients = store.get_recipients("foo")
        self.assertEqual(recipients, ["deadbeef01234567"])

    def test_get_recipients_no_gpg_id_raises(self):
        with tempfile.TemporaryDirectory() as d:
            store_path = Path(d)
            config = _gnupg_config(store_path)
            with (
                mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.secretstore.load_secretstore_config",
                    return_value=config,
                ),
                mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.secretstore.build_backend"
                ) as build,
            ):
                build.return_value = mock.MagicMock()
                store = SecretStore(
                    password_store_path=store_path,
                    generate=SecretGenerator(),
                )
                with self.assertRaises(FileNotFoundError):
                    store.get_recipients("foo")
