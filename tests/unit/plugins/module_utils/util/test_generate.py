# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.util.generate."""

import unittest

from ansible_collections.famedly.base.plugins.module_utils.util.generate import (
    SecretGenerator,
    UserSuppliedSecretMissingError,
    ALLOWED_SECRET_TYPES,
)


class TestSecretGenerator(unittest.TestCase):
    def test_random_plain_default_returns_string(self):
        gen = SecretGenerator(secret_type="random", data_type="plain")
        data = gen.get_data()
        self.assertIsInstance(data, str)
        self.assertEqual(len(data), 30)

    def test_random_with_length(self):
        gen = SecretGenerator(secret_type="random", data_type="plain", length=10)
        data = gen.get_data()
        self.assertEqual(len(data), 10)

    def test_user_supplied_returns_value(self):
        gen = SecretGenerator(
            secret_type="user_supplied",
            data_type="plain",
            user_supplied_secret="my-secret",
        )
        self.assertEqual(gen.get_data(), "my-secret")

    def test_user_supplied_none_raises(self):
        gen = SecretGenerator(
            secret_type="user_supplied",
            data_type="plain",
            user_supplied_secret=None,
        )
        with self.assertRaises(UserSuppliedSecretMissingError):
            gen.get_data()

    def test_binary_runs_command(self):
        gen = SecretGenerator(
            secret_type="binary",
            data_type="plain",
            binary="printf hello",
        )
        data = gen.get_data()
        self.assertEqual(data, "hello")

    def test_binary_none_raises(self):
        gen = SecretGenerator(secret_type="binary", data_type="plain", binary=None)
        with self.assertRaises(ValueError):
            gen.get_data()

    def test_invalid_secret_type_raises(self):
        with self.assertRaises(ValueError):
            SecretGenerator(secret_type="invalid", data_type="plain")  # type: ignore[invalid-argument-type]

    def test_invalid_data_type_raises(self):
        with self.assertRaises(ValueError):
            SecretGenerator(secret_type="random", data_type="xml")  # type: ignore[invalid-argument-type]

    def test_json_data_type_decodes(self):
        gen = SecretGenerator(
            secret_type="user_supplied",
            data_type="json",
            user_supplied_secret='{"a": 1}',
        )
        data = gen.get_data()
        self.assertEqual(data, {"a": 1})

    def test_allowed_secret_types(self):
        self.assertIn("random", ALLOWED_SECRET_TYPES)
        self.assertIn("binary", ALLOWED_SECRET_TYPES)
        self.assertIn("user_supplied", ALLOWED_SECRET_TYPES)
