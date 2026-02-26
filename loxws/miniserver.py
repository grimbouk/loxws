"""Represent the Loxone Miniserver websocket protocol client."""

from __future__ import annotations

import asyncio
import binascii
import logging
import os
import re
import ssl
import urllib.parse
import uuid
from base64 import b64decode, b64encode

import aiohttp
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA

from .auth import build_auth_hash, hash_password, normalize_hash_algorithm
from .configdata import ConfigData
from .messagebody import MessageBody
from .messageheader import MessageHeader
from .wsclient import STATE_RUNNING, WSClient

_LOGGER = logging.getLogger(__name__)

DEFAULT_TOKEN_PERMISSIONS = "4"
DEFAULT_CLIENT_INFO = "Home Assistant Loxone"

KEYEXCHANGE_MODES = ("pkcs1_v1_5_raw", "pkcs1_v1_5_url", "oaep_raw", "oaep_url")
AUTH_MODES = (
    ("getjwt", "server", "4"),
    ("gettoken", "server", "4"),
    ("getjwt", "server", "2"),
    ("gettoken", "server", "2"),
    ("getjwt", "sha1", "4"),
    ("gettoken", "sha1", "4"),
    ("getjwt", "sha256", "4"),
    ("gettoken", "sha256", "4"),
)


class Miniserver:
    """Loxone Miniserver client with token/JWT auth over websocket."""

    def __init__(
        self,
        host=None,
        port=None,
        username=None,
        password=None,
        use_tls=True,
        verify_tls=False,
        client_uuid=None,
        client_info=DEFAULT_CLIENT_INFO,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.verify_tls = verify_tls
        self.client_uuid = client_uuid or str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{host}:{username}"))
        self.client_info = client_info

        self.message_header = None
        self.message_body = None
        self.config_data = None

        self.public_key = None
        self._public_key_pem = None
        self._aes_key_hex = None
        self._aes_iv_hex = None
        self._command_salt = None
        self._server_key = None
        self._server_salt = None
        self._server_hash_alg = "sha256"
        self._token = None
        self._http_ssl_param = None
        self._waiting_auth = False

        self._keyexchange_mode_idx = 0
        self._auth_mode_idx = 0
        self._auth_failed_event = asyncio.Event()

        self.ready = asyncio.Event()
        self._handshake_lock = asyncio.Lock()
        self._command_lock = asyncio.Lock()
        self._keep_alive_task = None
        self._connected = False
        self._authenticated = False

    def connect(self, loop, connection_status):
        """Connect to the miniserver."""
        self.loop = loop
        self.async_connection_status_callback = connection_status
        self.wsclient = WSClient(
            self.loop,
            self.host,
            self.port,
            self.username,
            self.password,
            self.async_session_handler,
            self.async_message_handler,
            use_tls=self.use_tls,
            verify_tls=self.verify_tls,
        )
        self.wsclient.start()

    def shutdown(self):
        """Stop websocket and keep-alive."""
        self._connected = False
        self._authenticated = False
        if self._keep_alive_task is not None:
            self._keep_alive_task.cancel()
            self._keep_alive_task = None
        if hasattr(self, "wsclient"):
            self.wsclient.stop()

    async def wait_until_ready(self, timeout=45):
        """Wait until connection is authenticated and LoxAPP3 is loaded."""
        ready_task = self.loop.create_task(self.ready.wait())
        failed_task = self.loop.create_task(self._auth_failed_event.wait())
        done, pending = await asyncio.wait(
            {ready_task, failed_task},
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

        if not done:
            raise TimeoutError("Timed out waiting for miniserver readiness")
        if failed_task in done and failed_task.result():
            raise PermissionError("Miniserver authentication failed")

        if self._keep_alive_task is None:
            self._keep_alive_task = self.loop.create_task(self.keep_alive())

    def async_session_handler(self, state):
        _LOGGER.debug("ws session state=%s", state)
        if state == STATE_RUNNING:
            self._connected = True
            self._authenticated = False
            self._waiting_auth = False
            self._auth_mode_idx = 0
            self._keyexchange_mode_idx = 0
            self._auth_failed_event.clear()
            self.ready.clear()
            self.async_connection_status_callback(False)
            self.loop.create_task(self._async_begin_handshake())
        else:
            self._connected = False
            self._authenticated = False
            self._waiting_auth = False
            self.ready.clear()
            self.async_connection_status_callback(False)

    async def _async_begin_handshake(self):
        async with self._handshake_lock:
            try:
                self._prepare_session_crypto()
                if self.public_key is None:
                    public_key = await self._async_get_public_key()
                    self.public_key = RSA.import_key(public_key)

                ws = getattr(self.wsclient, "ws", None)
                if ws is None or ws.closed:
                    _LOGGER.debug("Skip keyexchange send because websocket is not ready")
                    return

                self._send_keyexchange()
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.error("Handshake start failed: %s", err)

    async def _async_get_public_key(self) -> str:
        if isinstance(self._public_key_pem, str) and self._public_key_pem:
            return self._public_key_pem

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.port}/jdev/sys/getPublicKey"
        ssl_param = await self._async_http_ssl_param()

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=ssl_param) as response:
                response.raise_for_status()
                payload = await response.json(content_type=None)

        raw_value = payload.get("LL", {}).get("value")
        self._public_key_pem = self._normalize_public_key(raw_value)
        return self._public_key_pem

    async def _async_http_ssl_param(self):
        if not self.use_tls:
            return None
        if not self.verify_tls:
            # keep HTTPS transport but disable cert validation for local/self-signed setups
            return False
        if self._http_ssl_param is None:
            self._http_ssl_param = await asyncio.to_thread(ssl.create_default_context)
        return self._http_ssl_param

    @staticmethod
    def _normalize_public_key(raw_value):
        if isinstance(raw_value, dict):
            raw_value = raw_value.get("key") or raw_value.get("publicKey") or raw_value.get("value")
        if not isinstance(raw_value, str):
            raise ValueError("getPublicKey did not return a string value")

        key_text = raw_value.strip().replace("\\r", "").replace("\\n", "\n")
        if not key_text:
            raise ValueError("getPublicKey returned an empty key")

        # Normalize PEM bodies that are in one line or contain extra whitespace.
        for marker in ("PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE"):
            begin = f"-----BEGIN {marker}-----"
            end = f"-----END {marker}-----"
            if begin in key_text and end in key_text:
                body = key_text.split(begin, 1)[1].split(end, 1)[0]
                body = re.sub(r"\s+", "", body)
                return f"{begin}\n{body}\n{end}"

        # Handle responses that only return the key body.
        key_body = re.sub(r"\s+", "", key_text)
        return f"-----BEGIN PUBLIC KEY-----\n{key_body}\n-----END PUBLIC KEY-----"

    def _prepare_session_crypto(self):
        # Loxone keyexchange uses AES-128 key + IV as hex in RSA payload.
        self._aes_key_hex = os.urandom(16).hex()
        self._aes_iv_hex = os.urandom(16).hex()
        self._command_salt = None
        self._waiting_auth = False

    def _keyexchange_mode(self):
        return KEYEXCHANGE_MODES[self._keyexchange_mode_idx]

    def _send_keyexchange(self):
        self.wsclient.send(f"jdev/sys/keyexchange/{self._encrypted_session_key()}")

    def _try_next_keyexchange_mode(self) -> bool:
        """Advance keyexchange mode and resend while modes remain."""
        current_idx = self._keyexchange_mode_idx
        current_mode = KEYEXCHANGE_MODES[current_idx]
        next_idx = current_idx + 1
        if next_idx >= len(KEYEXCHANGE_MODES):
            _LOGGER.debug("All keyexchange modes exhausted; authentication failed")
            self._auth_failed_event.set()
            return False

        next_mode = KEYEXCHANGE_MODES[next_idx]
        self._keyexchange_mode_idx = next_idx
        self._prepare_session_crypto()
        _LOGGER.debug(
            "Keyexchange rejected with 401 using mode '%s'; retrying mode '%s'",
            current_mode,
            next_mode,
        )
        self._send_keyexchange()
        return True

    def _encrypted_session_key(self):
        payload = f"{self._aes_key_hex}:{self._aes_iv_hex}".encode("utf-8")

        mode = self._keyexchange_mode()
        if mode.startswith("oaep"):
            cipher = PKCS1_OAEP.new(self.public_key)
        else:
            cipher = PKCS1_v1_5.new(self.public_key)

        encrypted = cipher.encrypt(payload)
        session_key = b64encode(encrypted).decode("utf-8")
        if mode.endswith("_url"):
            return urllib.parse.quote(session_key, safe="")
        return session_key

    def _send_auth_command(self, endpoint: str, hash_mode: str, permissions: str) -> bool:
        if not self._server_key or not self._server_salt:
            return False

        effective_alg = self._server_hash_alg if hash_mode == "server" else hash_mode
        try:
            password_hash = hash_password(self.password, self._server_salt, effective_alg)
            auth_hash = build_auth_hash(self.username, password_hash, self._server_key, effective_alg)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug(
                "Failed building auth command (%s/%s/%s): %s",
                endpoint,
                effective_alg,
                permissions,
                err,
            )
            return False

        info = urllib.parse.quote(self.client_info, safe="")
        if endpoint == "gettoken":
            command = (
                f"jdev/sys/gettoken/{auth_hash}/{self.username}/"
                f"{permissions}/{self.client_uuid}/{info}"
            )
        else:
            command = (
                f"jdev/sys/getjwt/{auth_hash}/{self.username}/"
                f"{permissions}/{self.client_uuid}/{info}"
            )

        self._waiting_auth = True
        _LOGGER.debug(
            "Sending auth endpoint='%s' hash_alg='%s' permissions='%s' (mode='%s')",
            endpoint,
            effective_alg,
            permissions,
            hash_mode,
        )
        self.wsclient.send(self.encrypt_command(command))
        return True

    def _send_next_auth_mode(self) -> bool:
        idx = int(self._auth_mode_idx)
        if idx >= len(AUTH_MODES):
            _LOGGER.debug("All auth modes exhausted without success")
            self._waiting_auth = False
            self._auth_failed_event.set()
            return False

        endpoint, hash_mode, permissions = AUTH_MODES[idx]
        self._auth_mode_idx = idx + 1
        return self._send_auth_command(endpoint, hash_mode, permissions)

    def async_message_handler(self, message, is_binary):
        try:
            if is_binary:
                self._process_binary_message(message)
                return
            self._process_text_message(message)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Failed to process message: %s", err)

    def _process_binary_message(self, message):
        if len(message) == 8 and message[0] == 3:
            self.message_header = MessageHeader(message)
            return
        if self.message_header is None:
            return
        if self.message_header.msg_type in {
            "Value-States",
            "Text-States",
            "Daytime-States",
            "Weather-States",
        } and self.config_data is None:
            return
        self.message_body = MessageBody(message, True, self.message_header, self.config_data)
        control = getattr(self.message_body, "control", "")
        if "LoxAPP3.json" in control:
            _LOGGER.debug("PROCESS LoxAPP3 binary response")
            self.config_data = ConfigData(self.message_body.msg)
            self.wsclient.send(self.encrypt_command("jdev/sps/enablebinstatusupdate"))

    def _process_text_message(self, message):
        if self.message_header is None:
            # Fallback header for text responses if no preceding header was parsed.
            class _FallbackHeader:
                msg_type = "Text"

            self.message_header = _FallbackHeader()

        decoded = message
        if not isinstance(message, str) or not message.startswith("{"):
            decrypted = self.decrypt_message(message)
            if decrypted is None:
                return
            decoded = decrypted

        self.message_body = MessageBody(decoded, False, self.message_header, self.config_data)
        control = getattr(self.message_body, "control", "")
        ll = self.message_body.msg.get("LL", {}) if isinstance(self.message_body.msg, dict) else {}
        code = str(ll.get("Code", ll.get("code", "")))
        value = ll.get("value")

        if control and any(
            token in control
            for token in (
                "keyexchange",
                "getkey2",
                "getjwt",
                "gettoken",
                "LoxAPP3.json",
                "enablebinstatusupdate",
            )
        ):
            _LOGGER.debug("Processed websocket control='%s' code='%s'", control, code)

        if "keyexchange" in control:
            if code == "401":
                self._try_next_keyexchange_mode()
                return

            self._auth_mode_idx = 0
            self.wsclient.send(self.encrypt_command(f"jdev/sys/getkey2/{self.username}"))
            return

        if "getkey2" in control:
            if not isinstance(value, dict):
                return

            self._server_key = value.get("key")
            self._server_salt = value.get("salt")
            raw_alg = value.get("hashAlg", value.get("hashalg"))
            self._server_hash_alg = normalize_hash_algorithm(raw_alg)
            _LOGGER.debug(
                "getkey2 hash algorithm raw='%s' effective='%s'",
                raw_alg,
                self._server_hash_alg,
            )
            self._auth_mode_idx = 0
            self._send_next_auth_mode()
            return

        if "getjwt" in control or "gettoken" in control:
            self._waiting_auth = False
            if code != "200":
                _LOGGER.debug(
                    "Auth endpoint rejected (control='%s' code=%s); trying next auth mode index=%s",
                    control,
                    code,
                    self._auth_mode_idx,
                )
                self._send_next_auth_mode()
                return

            self._auth_mode_idx = 0
            self._auth_failed_event.clear()
            self._token = value.get("token") if isinstance(value, dict) else None
            self._authenticated = True
            self.wsclient.send("data/LoxAPP3.json")
            return

        if "jdev/sys/fenc/" in control and code == "401" and not self._authenticated:
            if self._waiting_auth:
                self._waiting_auth = False
                _LOGGER.debug(
                    "Encrypted auth response 401; trying next auth mode index=%s",
                    self._auth_mode_idx,
                )
                self._send_next_auth_mode()
            return

        if "LoxAPP3.json" in control:
            self.config_data = ConfigData(self.message_body.msg)
            self.wsclient.send(self.encrypt_command("jdev/sps/enablebinstatusupdate"))
            return

        if "enablebinstatusupdate" in control:
            self.ready.set()
            self.async_connection_status_callback(True)
            return

    def send_command(self, command):
        self.wsclient.send(self.encrypt_command(command))

    async def send_command_with_response(self, command):
        async with self._command_lock:
            self.wsclient.send(self.encrypt_command(command))

    async def keep_alive(self):
        while True:
            await asyncio.sleep(240)
            if self._connected:
                self.wsclient.send("keepalive")

    def encrypt_command(self, command):
        if self._aes_key_hex is None or self._aes_iv_hex is None:
            raise RuntimeError("Session key/iv is not initialized")

        next_salt = os.urandom(2).hex()
        if self._command_salt is None:
            salted_command = f"salt/{next_salt}/{command}"
        else:
            salted_command = f"nextSalt/{self._command_salt}/{next_salt}/{command}"
        self._command_salt = next_salt

        key = binascii.unhexlify(self._aes_key_hex)
        iv = binascii.unhexlify(self._aes_iv_hex)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)

        padding_len = AES.block_size - (len(salted_command) % AES.block_size)
        padded_command = salted_command + ("\x00" * padding_len)
        encrypted = cipher_aes.encrypt(padded_command.encode("utf-8"))
        encoded = b64encode(encrypted)
        urlencoded = urllib.parse.quote(encoded, safe="")
        return f"jdev/sys/fenc/{urlencoded}"

    def decrypt_message(self, message):
        if self._aes_key_hex is None or self._aes_iv_hex is None:
            return None
        try:
            encrypted = b64decode(message)
            key = binascii.unhexlify(self._aes_key_hex)
            iv = binascii.unhexlify(self._aes_iv_hex)
            cipher_aes = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher_aes.decrypt(encrypted).rstrip(b"\x00")
            return decrypted.decode("utf-8")
        except Exception:  # pylint: disable=broad-except
            return None
