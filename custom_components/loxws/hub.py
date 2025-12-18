"""Coordinator-style hub for the Loxone integration."""

from __future__ import annotations

import logging
from typing import Any, Dict

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from loxws.client import LoxoneClient
from loxws.auth import LoxoneAuthError

from .const import DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


class LoxoneHub:
    """Manage websocket connection and state refreshes."""

    def __init__(self, hass: HomeAssistant, session, config: Dict[str, Any]) -> None:
        self._hass = hass
        self._config = config
        self._client = LoxoneClient(
            session,
            config["host"],
            config["port"],
            config["username"],
            config["password"],
            message_callback=self._handle_message,
        )
        self.coordinator = DataUpdateCoordinator[
            Dict[str, Any]
        ](
            hass,
            _LOGGER,
            name="loxws",
            update_method=self._async_update_data,
            update_interval=self._config.get("scan_interval", DEFAULT_SCAN_INTERVAL),
        )

    async def async_setup(self) -> None:
        """Connect to the websocket and prime the coordinator."""

        await self._client.async_connect()
        await self.coordinator.async_config_entry_first_refresh()

    async def async_close(self) -> None:
        """Close the websocket connection."""

        await self._client.async_close()

    async def _async_update_data(self) -> Dict[str, Any]:
        """Pull configuration data from the miniserver."""

        try:
            return await self._client.async_get_json("data/LoxAPP3.json")
        except (LoxoneAuthError, OSError) as err:
            raise UpdateFailed(f"Error communicating with Loxone: {err}") from err

    def _handle_message(self, message_type: str, payload: Any) -> None:
        """Handle push updates from the websocket connection."""

        _LOGGER.debug("Received %s message from Loxone", message_type)
        # Push updates will land here; platform entities can subscribe in follow-up work.
