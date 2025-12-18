"""Authentication helpers for Loxone websocket sessions."""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Optional

import aiohttp

DEFAULT_TOKEN_SAFETY_WINDOW = dt.timedelta(minutes=2)
DEFAULT_TOKEN_LIFETIME = dt.timedelta(minutes=30)


class LoxoneAuthError(Exception):
    """Raised when authentication against the miniserver fails."""


class LoxoneAuth:
    """Handle token based authentication and refresh for Loxone."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        token_safety_window: dt.timedelta = DEFAULT_TOKEN_SAFETY_WINDOW,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._token: Optional[str] = None
        self._token_expires: Optional[dt.datetime] = None
        self._token_lock = asyncio.Lock()
        self._token_safety_window = token_safety_window

    @property
    def token(self) -> Optional[str]:
        """Return the cached token value."""

        return self._token

    @property
    def token_expires(self) -> Optional[dt.datetime]:
        """Return the cached token expiry."""

        return self._token_expires

    async def async_get_token(self) -> str:
        """Return a valid token, refreshing if necessary."""

        async with self._token_lock:
            if self._token and self._token_expires:
                now = dt.datetime.now(dt.timezone.utc)
                if self._token_expires - self._token_safety_window > now:
                    return self._token

            return await self.async_refresh_token()

    async def async_refresh_token(self) -> str:
        """Request a new token from the miniserver."""

        url = f"http://{self._host}:{self._port}/jdev/sys/getjwt"  # JWT is available from 12.0+
        auth = aiohttp.BasicAuth(self._username, self._password)

        async with self._session.get(url, auth=auth) as resp:
            if resp.status != 200:
                raise LoxoneAuthError(f"Unexpected response when requesting token: {resp.status}")

            data = await resp.json()

        token = data.get("LL", {}).get("value", {}).get("token")
        valid_until = data.get("LL", {}).get("value", {}).get("validUntil")

        if not token:
            raise LoxoneAuthError("Token not returned from miniserver")

        expires = self._parse_expiry(valid_until)
        self._token = token
        self._token_expires = expires
        return token

    def _parse_expiry(self, value: Optional[int]) -> dt.datetime:
        """Normalize expiry into a timezone aware datetime."""

        if value:
            return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)

        return dt.datetime.now(dt.timezone.utc) + DEFAULT_TOKEN_LIFETIME
