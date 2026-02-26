"""Unit tests for TLS handling and public key normalization."""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "loxws")))

from wsclient import WSClient

try:
    from miniserver import Miniserver
except ModuleNotFoundError:
    Miniserver = None


def _noop(*_args, **_kwargs):
    return None


class TestTLSHandling(unittest.IsolatedAsyncioTestCase):
    """Verify TLS parameters are resolved correctly."""

    async def test_wsclient_tls_disabled_returns_none(self):
        client = WSClient(
            asyncio.get_running_loop(),
            "host",
            443,
            "user",
            "pass",
            _noop,
            _noop,
            use_tls=False,
            verify_tls=False,
        )
        self.assertIsNone(await client._resolve_ssl_param())

    async def test_wsclient_verify_false_returns_false_without_context(self):
        client = WSClient(
            asyncio.get_running_loop(),
            "host",
            443,
            "user",
            "pass",
            _noop,
            _noop,
            use_tls=True,
            verify_tls=False,
        )
        with patch("wsclient.ssl.create_default_context", side_effect=AssertionError("should not be called")):
            self.assertFalse(await client._resolve_ssl_param())

    async def test_wsclient_verify_true_caches_context(self):
        sentinel = object()
        client = WSClient(
            asyncio.get_running_loop(),
            "host",
            443,
            "user",
            "pass",
            _noop,
            _noop,
            use_tls=True,
            verify_tls=True,
        )
        with patch("wsclient.ssl.create_default_context", return_value=sentinel) as mocked:
            first = await client._resolve_ssl_param()
            second = await client._resolve_ssl_param()
        self.assertIs(first, sentinel)
        self.assertIs(second, sentinel)
        self.assertEqual(mocked.call_count, 1)

    async def test_miniserver_verify_false_returns_false_without_context(self):
        if Miniserver is None:
            self.skipTest("pycryptodome not installed in local test environment")
        ms = Miniserver(host="host", port=443, username="user", password="pass", use_tls=True, verify_tls=False)
        with patch("miniserver.ssl.create_default_context", side_effect=AssertionError("should not be called")):
            self.assertFalse(await ms._async_http_ssl_param())


@unittest.skipIf(Miniserver is None, "pycryptodome not installed in local test environment")
class TestPublicKeyNormalization(unittest.TestCase):
    """Verify getPublicKey payload normalization."""

    def test_normalize_public_key_escaped_pem(self):
        raw = "-----BEGIN PUBLIC KEY-----\\nAB CDE F==\\n-----END PUBLIC KEY-----"
        normalized = Miniserver._normalize_public_key(raw)
        self.assertEqual(
            normalized,
            "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----",
        )

    def test_normalize_public_key_raw_body(self):
        normalized = Miniserver._normalize_public_key("AB CD EF==")
        self.assertEqual(
            normalized,
            "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----",
        )

    def test_normalize_public_key_from_dict_value(self):
        normalized = Miniserver._normalize_public_key({"key": "AB CD EF=="})
        self.assertEqual(
            normalized,
            "-----BEGIN PUBLIC KEY-----\nABCDEF==\n-----END PUBLIC KEY-----",
        )


if __name__ == "__main__":
    unittest.main()
