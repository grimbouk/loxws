"""Config flow for the Loxone websocket integration."""

from __future__ import annotations

import logging
from typing import Any, Dict

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from loxws.auth import LoxoneAuthError
from loxws.client import LoxoneClient

from .const import DEFAULT_PORT, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def _validate_input(hass: HomeAssistant, data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the user input allows us to connect."""

    session = async_get_clientsession(hass)
    client = LoxoneClient(
        session,
        data["host"],
        data.get("port", DEFAULT_PORT),
        data["username"],
        data["password"],
    )

    try:
        await client.auth.async_refresh_token()
    finally:
        await client.async_close()

    return data


class LoxoneConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Loxone websocket."""

    VERSION = 1

    async def async_step_user(self, user_input: Dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""

        errors: Dict[str, str] = {}

        if user_input is not None:
            try:
                info = await _validate_input(self.hass, user_input)
            except LoxoneAuthError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected exception validating Loxone configuration")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(info["host"])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["host"], data=info)

        data_schema = vol.Schema(
            {
                vol.Required("host"): str,
                vol.Optional("port", default=DEFAULT_PORT): int,
                vol.Required("username"): str,
                vol.Required("password"): str,
            }
        )

        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
