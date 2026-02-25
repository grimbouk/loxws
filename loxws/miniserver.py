"""Represent the Loxone Miniserver websocket protocol client."""

from __future__ import annotations

import asyncio
import binascii
import logging
import os
import urllib.parse
import uuid
from base64 import b64decode, b64encode

import aiohttp
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

from .auth import build_auth_hash, hash_password, normalize_hash_algorithm
from .configdata import ConfigData
from .messagebody import MessageBody
from .messageheader import MessageHeader
from .wsclient import STATE_RUNNING, WSClient

_LOGGER = logging.getLogger(__name__)

DEFAULT_TOKEN_PERMISSIONS = "4"
DEFAULT_CLIENT_INFO = "Home Assistant Loxone"
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
        self._aes_key_hex = None
        self._aes_iv_hex = None
        self._server_key = None
        self._server_salt = None
        self._hash_alg = "sha256"
        self._token = None

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
        await asyncio.wait_for(self.ready.wait(), timeout=timeout)
        if self._keep_alive_task is None:
            self._keep_alive_task = self.loop.create_task(self.keep_alive())

    def async_session_handler(self, state):
        _LOGGER.debug("ws session state=%s", state)
        if state == STATE_RUNNING:
            self._connected = True
            self._authenticated = False
            self.ready.clear()
            self.async_connection_status_callback(False)
            self.loop.create_task(self._async_begin_handshake())
        else:
            self._connected = False
            self._authenticated = False
            self.ready.clear()
            self.async_connection_status_callback(False)

    async def _async_begin_handshake(self):
        async with self._handshake_lock:
            try:
                self._prepare_session_crypto()
                public_key = await self._async_get_public_key()
                self.public_key = RSA.import_key(public_key)
                command = f"jdev/sys/keyexchange/{self._encrypted_session_key()}"
                _LOGGER.debug("SEND keyexchange")
                self.wsclient.send(command)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.error("Handshake start failed: %s", err)

    async def _async_get_public_key(self) -> str:
        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.port}/jdev/sys/getPublicKey"
        ssl_ctx = None
        if self.use_tls and not self.verify_tls:
            import ssl

            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=ssl_ctx) as response:
                response.raise_for_status()
                payload = await response.json(content_type=None)

        key_value = payload["LL"]["value"]
        if "BEGIN" in key_value:
            return key_value
        return f"-----BEGIN PUBLIC KEY-----\n{key_value}\n-----END PUBLIC KEY-----"

    def _prepare_session_crypto(self):
        self._aes_key_hex = os.urandom(32).hex()
        self._aes_iv_hex = os.urandom(16).hex()

    def _encrypted_session_key(self):
        payload = f"{self._aes_key_hex}:{self._aes_iv_hex}".encode("utf-8")
        cipher = PKCS1_v1_5.new(self.public_key)
        encrypted = cipher.encrypt(payload)
        session_key = b64encode(encrypted).decode("utf-8")
        return urllib.parse.quote(session_key, safe="")

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
        decoded = message
        if not message.startswith("{"):
            decrypted = self.decrypt_message(message)
            if decrypted is None:
                return
            decoded = decrypted

        if self.message_header is None:
            # Fallback header for text responses if no preceding header was parsed.
            class _FallbackHeader:
                msg_type = "Text"

            self.message_header = _FallbackHeader()

        self.message_body = MessageBody(decoded, False, self.message_header, self.config_data)
        control = getattr(self.message_body, "control", "")
        code = str(self.message_body.msg.get("LL", {}).get("Code", self.message_body.msg.get("LL", {}).get("code", "")))
        value = self.message_body.msg.get("LL", {}).get("value")

        if "keyexchange" in control:
            _LOGGER.debug("PROCESS keyexchange response (code=%s)", code)
            command = f"jdev/sys/getkey2/{self.username}"
            self.wsclient.send(self.encrypt_command(command))
            return

        if "getkey2" in control:
            _LOGGER.debug("PROCESS getkey2 response (code=%s)", code)
            self._server_key = value["key"]
            self._server_salt = value["salt"]
            self._hash_alg = normalize_hash_algorithm(value.get("hashAlg"))
            pw_hash = hash_password(self.password, self._server_salt, self._hash_alg)
            auth_hash = build_auth_hash(self.username, pw_hash, self._server_key, self._hash_alg)
            info = urllib.parse.quote(self.client_info, safe="")
            command = (
                f"jdev/sys/getjwt/{auth_hash}/{self.username}/"
                f"{DEFAULT_TOKEN_PERMISSIONS}/{self.client_uuid}/{info}"
            )
            self.wsclient.send(self.encrypt_command(command))
            return

        if "getjwt" in control:
            _LOGGER.debug("PROCESS getjwt response (code=%s)", code)
            if code != "200":
                _LOGGER.error("JWT acquisition failed: %s", self.message_body.raw)
                return
            self._token = value.get("token") if isinstance(value, dict) else None
            self._authenticated = True
            self.wsclient.send("data/LoxAPP3.json")
            return

        if "LoxAPP3.json" in control:
            _LOGGER.debug("PROCESS LoxAPP3 response")
            self.config_data = ConfigData(self.message_body.msg)
            self.wsclient.send(self.encrypt_command("jdev/sps/enablebinstatusupdate"))
            return

        if "enablebinstatusupdate" in control:
            _LOGGER.debug("PROCESS enablebinstatusupdate response (code=%s)", code)
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

        salt = os.urandom(2).hex()
        salted_command = f"salt/{salt}/{command}"

        key = binascii.unhexlify(self._aes_key_hex)
        iv = binascii.unhexlify(self._aes_iv_hex)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)

        padding_len = AES.block_size - (len(salted_command) % AES.block_size)
        padded_salted_command = salted_command + ("\x00" * padding_len)
        encrypted = cipher_aes.encrypt(padded_salted_command.encode("utf-8"))
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
