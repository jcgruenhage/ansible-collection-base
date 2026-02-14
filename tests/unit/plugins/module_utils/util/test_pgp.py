# (c) 2026, JC Grünhage
# GNU Affero General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/agpl-3.0.txt)

"""Unit tests for module_utils.util.pgp."""

import tempfile
import unittest
from pathlib import Path

import pytest

from pgpy import PGPKey, PGPMessage

from ansible_collections.famedly.base.plugins.module_utils.util.pgp import (
    validate_fingerprint_or_keyid,
    iter_cert_paths_in_pgp_cert_d,
    get_recipient_key_ids,
    cert_fingerprints_and_keyids,
    find_cert_in_pgp_cert_d,
    resolve_fingerprint_to_pgp_cert_d_path,
    diff_recipients,
)


class TestValidateFingerprintOrKeyid(unittest.TestCase):
    def test_valid_40_char_returns_fingerprint(self):
        self.assertEqual(validate_fingerprint_or_keyid("a" * 40), "fingerprint")
        self.assertEqual(
            validate_fingerprint_or_keyid("0123456789abcdef" * 2 + "01234567"),
            "fingerprint",
        )
        self.assertEqual(
            validate_fingerprint_or_keyid("ABCDEF0123456789" * 2 + "ABCDEF01"),
            "fingerprint",
        )

    def test_valid_16_char_returns_keyid(self):
        self.assertEqual(validate_fingerprint_or_keyid("a" * 16), "keyid")

    def test_empty_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate_fingerprint_or_keyid("")
        self.assertIn("empty", str(ctx.exception))

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            validate_fingerprint_or_keyid("abc")
        with self.assertRaises(ValueError):
            validate_fingerprint_or_keyid("a" * 20)

    def test_non_hex_raises(self):
        with self.assertRaises(ValueError) as ctx:
            validate_fingerprint_or_keyid("g" + "a" * 39)
        self.assertIn("hex", str(ctx.exception))

    def test_normalizes_strip_lower(self):
        self.assertEqual(
            validate_fingerprint_or_keyid("  " + "A" * 40 + "  "), "fingerprint"
        )


class TestIterCertPathsInPgpCertD(unittest.TestCase):
    def test_empty_dir_yields_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            paths = list(iter_cert_paths_in_pgp_cert_d(Path(d)))
        self.assertEqual(paths, [])

    def test_yields_only_fingerprint_layout_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Valid: 2-char hex dir + 38-char hex filename = 40-char fingerprint
            (root / "ab").mkdir()
            (root / "ab" / "cdef1234567890123456789012345678901234").write_bytes(
                b"cert"
            )
            # Invalid: "xy" dir is not all hex (y is not 0-9a-f)
            (root / "xy").mkdir()
            (root / "xy" / "00112233445566778899aabbccddeeff001122").write_bytes(b"bad")
            # Valid: another correct entry
            (root / "00").mkdir()
            (root / "00" / "22334455667788990011aabbccddeeff0011aa").write_bytes(
                b"cert2"
            )
            paths = list(iter_cert_paths_in_pgp_cert_d(root))
        self.assertEqual(len(paths), 2)
        names = {p.name for p in paths}
        self.assertIn("cdef1234567890123456789012345678901234", names)
        self.assertIn("22334455667788990011aabbccddeeff0011aa", names)


def _generate_test_key():
    """Generate an Ed25519 primary key with a Curve25519 encryption subkey."""
    from pgpy import PGPUID
    from pgpy.constants import (
        CompressionAlgorithm,
        EllipticCurveOID,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    uid = PGPUID.new("Test <test@test>")
    key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[
            CompressionAlgorithm.ZLIB,
            CompressionAlgorithm.ZIP,
            CompressionAlgorithm.Uncompressed,
        ],
    )
    subkey = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
    key.add_subkey(
        subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
    )
    return key


class TestGetRecipientKeyIds(unittest.TestCase):
    @pytest.mark.filterwarnings("ignore:TripleDES")
    def test_returns_encrypter_key_ids_from_ciphertext(self):
        key = _generate_test_key()
        msg = PGPMessage.new("secret")
        encrypted = key.pubkey.encrypt(msg)
        ciphertext = bytes(encrypted)
        ids = get_recipient_key_ids(ciphertext)
        self.assertIsInstance(ids, list)
        self.assertEqual(len(ids), 1)
        self.assertEqual(len(ids[0]), 16)


class TestCertFingerprintsAndKeyids(unittest.TestCase):
    def test_returns_fingerprints_and_keyids(self):
        key = _generate_test_key()
        fps, keyids = cert_fingerprints_and_keyids(key)
        self.assertIsInstance(fps, set)
        self.assertIsInstance(keyids, set)
        # Primary key + encryption subkey = 2 each
        self.assertEqual(len(fps), 2)
        self.assertEqual(len(keyids), 2)
        for fp in fps:
            self.assertEqual(len(fp), 40)
        for kid in keyids:
            self.assertEqual(len(kid), 16)


class TestFindCertInPgpCertD(unittest.TestCase):
    def test_empty_cert_d_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            result = find_cert_in_pgp_cert_d(Path(d), "a" * 40)
        self.assertIsNone(result)


class TestResolveFingerprintToPgpCertDPath(unittest.TestCase):
    def test_cert_not_found_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as ctx:
                resolve_fingerprint_to_pgp_cert_d_path(Path(d), "a" * 40)
        self.assertIn("Could not resolve", str(ctx.exception))


class TestDiffRecipients(unittest.TestCase):
    def test_wanted_not_in_cert_store_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                diff_recipients(
                    ["a" * 16],
                    ["b" * 40],
                    Path(d),
                    sync_from_gpg_if_missing=False,
                )
