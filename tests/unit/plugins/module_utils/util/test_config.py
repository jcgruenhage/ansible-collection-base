# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.util.config."""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from ansible_collections.famedly.base.plugins.module_utils.util.config import (
    SecretStoreConfig,
    load_secretstore_config,
)
from ansible_collections.famedly.base.plugins.module_utils.util.config import (
    _CONFIG_DIR_NAME,
    _CONFIG_FILENAME,
    _RawSOPDecryptionConfig,
    _RawSecretStoreConfig,
    _VALID_BACKENDS,
    _get_config_file_path,
    _get_default_pgp_cert_d_path,
)


class TestGetConfigFilePath(unittest.TestCase):
    def test_returns_path_ending_with_config_yaml(self):
        p = _get_config_file_path()
        self.assertIsInstance(p, Path)
        self.assertEqual(p.name, _CONFIG_FILENAME)
        self.assertEqual(p.parent.name, _CONFIG_DIR_NAME)

    def test_linux_uses_xdg_config_home_when_set(self):
        if sys.platform != "linux2" and not sys.platform.startswith("linux"):
            self.skipTest("Linux only")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg"}, clear=False):
            p = _get_config_file_path()
            self.assertEqual(p.parent, Path("/xdg") / _CONFIG_DIR_NAME)


class TestGetDefaultPgpCertDPath(unittest.TestCase):
    def test_returns_path_containing_pgp_cert_d(self):
        p = _get_default_pgp_cert_d_path()
        self.assertIsInstance(p, Path)
        self.assertEqual(p.name, "pgp.cert.d")


class TestApplyOverridesFromEnv(unittest.TestCase):
    def test_sop_decryption_key_from_env(self):
        dec = _RawSOPDecryptionConfig()
        with mock.patch.dict(
            os.environ, {"TEST_SOP_DECRYPTION_KEY": "/tmp/key.asc"}, clear=False
        ):
            dec.apply_overrides_from_env("TEST_SOP_DECRYPTION")
        self.assertEqual(dec.key, Path("/tmp/key.asc"))

    def test_pgp_cert_d_from_env(self):
        config = _RawSecretStoreConfig()
        with mock.patch.dict(
            os.environ,
            {"ANSIBLE_OPENPGP_SECRETSTORE_PGP_CERT_D": "/tmp/cert.d"},
            clear=False,
        ):
            config.apply_overrides_from_env()
        self.assertEqual(config.pgp_cert_d, Path("/tmp/cert.d"))

    def test_root_backend_from_env_valid(self):
        config = _RawSecretStoreConfig()
        with mock.patch.dict(
            os.environ, {"ANSIBLE_OPENPGP_SECRETSTORE_BACKEND": "sop"}, clear=False
        ):
            config.apply_overrides_from_env()
        self.assertEqual(config.backend, "sop")

    def test_root_backend_from_env_invalid_raises(self):
        config = _RawSecretStoreConfig()
        with mock.patch.dict(
            os.environ, {"ANSIBLE_OPENPGP_SECRETSTORE_BACKEND": "invalid"}, clear=False
        ):
            with self.assertRaises(ValueError) as ctx:
                config.apply_overrides_from_env()
        self.assertIn("Invalid", str(ctx.exception))


class TestLoadSecretStoreConfig(unittest.TestCase):
    def test_missing_file_returns_validated_gnupg_config(self):
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = Path("/nonexistent/config.yaml")
            config = load_secretstore_config()
        self.assertIsInstance(config, SecretStoreConfig)
        self.assertEqual(config.backend, "gnupg")
        self.assertIsNone(config.sop)
        self.assertIsInstance(config.password_store_path, Path)
        self.assertIsInstance(config.pgp_cert_d_path, Path)

    def test_valid_yaml_gnupg_loads_and_validates(self):
        mock_path = mock.MagicMock(spec=Path)
        mock_path.is_file.return_value = True
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = mock_path
            with mock.patch(
                "ansible_collections.famedly.base.plugins.module_utils.util.config._RawSecretStoreConfig.from_yaml_file"
            ) as from_yaml:
                raw = _RawSecretStoreConfig(backend="gnupg")
                from_yaml.return_value = raw
                result = load_secretstore_config()
        self.assertIsInstance(result, SecretStoreConfig)
        self.assertEqual(result.backend, "gnupg")
        self.assertIsNone(result.sop)

    def test_password_store_path_arg_overrides_config(self):
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = Path("/nonexistent/config.yaml")
            config = load_secretstore_config(password_store_path=Path("/tmp/my-store"))
        self.assertEqual(
            str(config.password_store_path),
            str(Path("/tmp/my-store").resolve()),
        )


class TestLoadSecretStoreConfigValidation(unittest.TestCase):
    """Validation: incoherent SOP config raises; valid raw yields validated config."""

    def test_backend_sop_without_key_raises(self):
        """backend=sop with no decryption key must raise."""
        mock_path = mock.MagicMock(spec=Path)
        mock_path.is_file.return_value = True
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = mock_path
            with mock.patch(
                "ansible_collections.famedly.base.plugins.module_utils.util.config._RawSecretStoreConfig.from_yaml_file"
            ) as from_yaml:
                raw = _RawSecretStoreConfig(backend="sop")
                raw.sop.decryption.key = None
                raw.sop.exec = Path("/usr/bin/rsop")
                from_yaml.return_value = raw
                with self.assertRaises(ValueError) as ctx:
                    load_secretstore_config()
                self.assertIn("sop.decryption.key", str(ctx.exception))

    def test_sop_intent_without_executables_raises(self):
        """sop.decryption.key set but no executables: intent to use SOP, must raise."""
        mock_path = mock.MagicMock(spec=Path)
        mock_path.is_file.return_value = True
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = mock_path
            with mock.patch(
                "ansible_collections.famedly.base.plugins.module_utils.util.config._RawSecretStoreConfig.from_yaml_file"
            ) as from_yaml:
                raw = _RawSecretStoreConfig(backend=None)
                raw.sop.decryption.key = Path("/tmp/key.asc")
                raw.sop.exec = None
                from_yaml.return_value = raw
                with mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.util.sop.resolve_sop_executable"
                ) as resolve_sop:
                    from ansible_collections.famedly.base.plugins.module_utils.util.sop import (
                        SOPExecutableNotConfiguredError,
                    )

                    resolve_sop.side_effect = SOPExecutableNotConfiguredError("x")
                    with self.assertRaises(ValueError) as ctx:
                        load_secretstore_config()
                    self.assertIn("executables", str(ctx.exception))

    def test_no_sop_intent_returns_gnupg(self):
        """No backend and no SOP options: validated backend is gnupg."""
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = Path("/nonexistent/config.yaml")
            config = load_secretstore_config()
        self.assertEqual(config.backend, "gnupg")
        self.assertIsNone(config.sop)

    def test_backend_sop_with_key_and_execs_returns_sop(self):
        """backend=sop with key and executables (mocked) yields validated sop config."""
        mock_path = mock.MagicMock(spec=Path)
        mock_path.is_file.return_value = True
        with mock.patch(
            "ansible_collections.famedly.base.plugins.module_utils.util.config._get_config_file_path"
        ) as m:
            m.return_value = mock_path
            with mock.patch(
                "ansible_collections.famedly.base.plugins.module_utils.util.config._RawSecretStoreConfig.from_yaml_file"
            ) as from_yaml:
                raw = _RawSecretStoreConfig(backend="sop")
                raw.sop.decryption.key = Path("/tmp/key.asc")
                raw.sop.exec = Path("/usr/bin/rsop")
                from_yaml.return_value = raw
                with mock.patch(
                    "ansible_collections.famedly.base.plugins.module_utils.util.sop.resolve_sop_executable"
                ) as resolve_sop:
                    resolve_sop.return_value = Path("/usr/bin/rsop")
                    config = load_secretstore_config()
        self.assertEqual(config.backend, "sop")
        self.assertIsNotNone(config.sop)
        assert config.sop is not None  # for type checker
        self.assertEqual(config.sop.encryption.exec, Path("/usr/bin/rsop"))
        self.assertEqual(config.sop.decryption.exec, Path("/usr/bin/rsop"))
        self.assertEqual(config.sop.decryption.key_path, Path("/tmp/key.asc").resolve())


class TestValidBackends(unittest.TestCase):
    def test_valid_backends_tuple(self):
        self.assertEqual(_VALID_BACKENDS, ("gnupg", "sop"))
