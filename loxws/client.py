"""Async client helpers for Loxone websocket access."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Optional

import aiohttp

from .auth import LoxoneAuth, LoxoneAuthError

_LOGGER = logging.getLogger(__name__)

MESSAGE_CALLBACK = Callable[[str, Any], None]


class LoxoneClient:
    """Coordinate authenticated websocket access to the miniserver."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        message_callback: Optional[MESSAGE_CALLBACK] = None,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._message_callback = message_callback
        self._auth = LoxoneAuth(session, host, port, username, password)
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._connected_event = asyncio.Event()

    @property
    def is_connected(self) -> bool:
        """Return connection status."""

        return self._ws is not None and not self._ws.closed

    @property
    def auth(self) -> LoxoneAuth:
        """Return the auth helper for the client."""

        return self._auth

    async def async_connect(self) -> None:
        """Open a websocket connection and start listening."""

        if self.is_connected:
            return

        token = await self._auth.async_get_token()
        url = f"ws://{self._host}:{self._port}/ws/rfc6455"
        headers = {"Authorization": f"Bearer {token}"}
        self._ws = await self._session.ws_connect(url, headers=headers, protocols=("remotecontrol",))
        self._connected_event.set()
        self._listener_task = asyncio.create_task(self._listen())

    async def _listen(self) -> None:
        """Listen for websocket events and dispatch callbacks."""

        assert self._ws is not None
        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    payload: Any = msg.data
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except ValueError:
                        payload = msg.data
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    _LOGGER.error("Websocket error: %s", msg.data)
                    break
                else:
                    continue

                if self._message_callback:
                    self._message_callback(msg.type.name, payload)
        finally:
            await self.async_close()

    async def async_send_command(self, command: str) -> None:
        """Send a command, refreshing the token if required."""

        await self._connected_event.wait()

        if not self._ws or self._ws.closed:
            await self.async_connect()

        assert self._ws is not None
        await self._auth.async_get_token()
        await self._ws.send_str(command)

    async def async_get_json(self, path: str, *, _retried: bool = False) -> Any:
        """Perform an authenticated HTTP GET returning JSON payload."""

        token = await self._auth.async_get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"http://{self._host}:{self._port}/{path}".rstrip("/")

        async with self._session.get(url, headers=headers) as resp:
            if resp.status == 401:
                if _retried:
                    raise LoxoneAuthError(
                        f"Authentication failed when fetching {path} after refreshing token"
                    )

                # Token expired, re-auth and retry once
                await self._auth.async_refresh_token()
                return await self.async_get_json(path, _retried=True)

            if resp.status != 200:
                raise LoxoneAuthError(f"Unexpected HTTP status {resp.status} when fetching {path}")

            return await resp.json()

    async def async_close(self) -> None:
        """Close the websocket and cleanup tasks."""

        if self._listener_task:
            self._listener_task.cancel()
            self._listener_task = None

        if self._ws and not self._ws.closed:
            await self._ws.close()

        self._ws = None
        self._connected_event.clear()
