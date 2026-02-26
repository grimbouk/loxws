"""Unit tests for Miniserver auth helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "loxws")))

from auth import build_auth_hash, hash_password, normalize_hash_algorithm


class TestMiniserverAuth(unittest.TestCase):
    """Protocol helper tests."""

    def test_hash_password_sha1(self):
        password = "secret"
        salt = "SALT1234"
        expected = hashlib.sha1(f"{password}:{salt}".encode("utf-8")).hexdigest().upper()
        self.assertEqual(hash_password(password, salt, "SHA1"), expected)

    def test_hash_password_sha256(self):
        password = "secret"
        salt = "SALT1234"
        expected = hashlib.sha256(f"{password}:{salt}".encode("utf-8")).hexdigest().upper()
        self.assertEqual(hash_password(password, salt, "SHA256"), expected)

    def test_build_auth_hash(self):
        username = "user"
        pw_hash = "ABC123"
        key_hex = "00112233445566778899aabbccddeeff"
        expected = hmac.new(
            bytes.fromhex(key_hex),
            f"{username}:{pw_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(build_auth_hash(username, pw_hash, key_hex, "SHA256"), expected)

    def test_normalize_hash_algorithm_missing_defaults_sha1(self):
        self.assertEqual(normalize_hash_algorithm(None), "sha1")

    def test_normalize_hash_algorithm_unknown_defaults_sha1(self):
        self.assertEqual(normalize_hash_algorithm("sha512"), "sha1")


if __name__ == "__main__":
    unittest.main()
