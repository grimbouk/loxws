"""Unit tests for Miniserver auth/keyexchange state transitions."""

from __future__ import annotations

import unittest

try:
    from loxws.miniserver import AUTH_MODES, KEYEXCHANGE_MODES, Miniserver
except ModuleNotFoundError:
    AUTH_MODES = ()
    KEYEXCHANGE_MODES = ()
    Miniserver = None


class _FakeWSClient:
    def __init__(self):
        self.sent: list[str] = []

    def send(self, message: str):
        self.sent.append(message)


@unittest.skipIf(Miniserver is None, "pycryptodome not installed in local test environment")
class TestAuthStateMachine(unittest.TestCase):
    """Validate auth retry behavior without reconnect loops."""

    def _new_miniserver(self) -> Miniserver:
        ms = Miniserver(host="host", port=443, username="lox.home", password="secret")
        ms.wsclient = _FakeWSClient()
        ms.encrypt_command = lambda command: command
        ms._aes_key_hex = "00" * 16
        ms._aes_iv_hex = "11" * 16
        return ms

    def test_auth_401_advances_to_next_mode(self):
        ms = self._new_miniserver()

        ms._process_text_message(
            '{"LL":{"control":"jdev/sys/getkey2/lox.home","Code":"200","value":'
            '{"key":"00112233445566778899aabbccddeeff","salt":"SALT","hashAlg":"SHA256"}}}'
        )
        self.assertTrue(ms.wsclient.sent)
        self.assertIn("jdev/sys/getjwt/", ms.wsclient.sent[-1])

        ms._process_text_message(
            '{"LL":{"control":"jdev/sys/getjwt/hash/lox.home/4/client/info","Code":"401","value":{}}}'
        )
        self.assertGreaterEqual(len(ms.wsclient.sent), 2)
        self.assertIn("jdev/sys/gettoken/", ms.wsclient.sent[-1])

    def test_exhausted_auth_modes_sets_failed_event(self):
        ms = self._new_miniserver()
        ms._server_key = "00112233445566778899aabbccddeeff"
        ms._server_salt = "SALT"
        ms._auth_mode_idx = len(AUTH_MODES)

        result = ms._send_next_auth_mode()
        self.assertFalse(result)
        self.assertTrue(ms._auth_failed_event.is_set())

    def test_keyexchange_401_cycles_modes_in_session(self):
        ms = self._new_miniserver()
        seen_modes: list[str] = []
        ms._send_keyexchange = lambda: seen_modes.append(ms._keyexchange_mode())

        for _ in range(len(KEYEXCHANGE_MODES) - 1):
            self.assertTrue(ms._try_next_keyexchange_mode())

        self.assertEqual(seen_modes, list(KEYEXCHANGE_MODES[1:]))
        self.assertFalse(ms._try_next_keyexchange_mode())
        self.assertTrue(ms._auth_failed_event.is_set())


if __name__ == "__main__":
    unittest.main()
