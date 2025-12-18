"""Constants for the Loxone websocket integration."""

from datetime import timedelta

DOMAIN = "loxws"
PLATFORMS: list[str] = []
DEFAULT_PORT = 80
DEFAULT_SCAN_INTERVAL = timedelta(seconds=30)
