"""Represent the websocket client session."""

from __future__ import annotations

import asyncio
import logging
import ssl

import aiohttp

_LOGGER = logging.getLogger(__name__)

STATE_STARTING = "starting"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
CONNECTING = "connecting"

RETRY_TIMER = 20


class WSClient:
    """Websocket client wrapper for Miniserver communication."""

    def __init__(
        self,
        loop,
        host,
        port,
        username,
        password,
        async_session_callback,
        async_message_callback,
        use_tls=True,
        verify_tls=False,
    ):
        self.loop = loop
        self.session = None
        self.ws = None
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.verify_tls = verify_tls
        self._state = None
        self.async_session_handler_callback = async_session_callback
        self.async_message_handler_callback = async_message_callback
        self._retry_handle = None

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value
        _LOGGER.debug("Set Websocket state: %s", value)
        self.async_session_handler_callback(self._state)

    def start(self):
        if self.state != STATE_RUNNING:
            self.state = STATE_STARTING
            self.loop.create_task(self.running())

    async def running(self):
        """Start websocket connection and message loop."""
        scheme = "wss" if self.use_tls else "ws"
        url = f"{scheme}://{self.host}:{self.port}/ws/rfc6455"
        _LOGGER.debug("Connecting websocket: %s", url)

        try:
            await self._async_close()
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=None)
            self.session = aiohttp.ClientSession(timeout=timeout)
            self.ws = await self.session.ws_connect(
                url,
                protocols=("remotecontrol",),
                ssl=self._ssl_context(),
                heartbeat=30,
                autoping=True,
            )
            self.state = STATE_RUNNING

            async for msg in self.ws:
                if self.state == STATE_STOPPED:
                    break
                if msg.type == aiohttp.WSMsgType.BINARY:
                    self.async_message_handler_callback(msg.data, True)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    self.async_message_handler_callback(msg.data, False)
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    _LOGGER.debug("Websocket closed by remote")
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    _LOGGER.debug("Websocket error frame: %s", self.ws.exception())
                    break
        except aiohttp.ClientConnectorError as err:
            _LOGGER.debug("ClientConnectorError: %s", err)
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Websocket error: %s", err)
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()
        else:
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()
        finally:
            await self._async_close()

    def retry(self):
        """Schedule reconnect attempt."""
        if self._retry_handle is not None:
            self._retry_handle.cancel()
        self._retry_handle = self.loop.call_later(RETRY_TIMER, self.start)
        _LOGGER.debug("Reconnecting in %i seconds.", RETRY_TIMER)

    def send(self, message):
        """Send a text websocket message."""
        if self.state == STATE_RUNNING and self.ws is not None and not self.ws.closed:
            self.loop.create_task(self.ws.send_str(message))
        else:
            _LOGGER.debug("Drop send while websocket not ready: %s", message)

    def stop(self):
        """Close websocket connection and stop reconnects."""
        self.state = STATE_STOPPED
        if self._retry_handle is not None:
            self._retry_handle.cancel()
            self._retry_handle = None
        self.loop.create_task(self._async_close())

    def _ssl_context(self):
        if not self.use_tls:
            return None
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _async_close(self):
        if self.ws is not None:
            try:
                await self.ws.close()
            except Exception:  # pylint: disable=broad-except
                pass
            self.ws = None
        if self.session is not None:
            try:
                await self.session.close()
            except Exception:  # pylint: disable=broad-except
                pass
            self.session = None
