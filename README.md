# loxws Package

Async Loxone websocket client with Home Assistant integration scaffolding. The library exposes an async `LoxoneClient` that handles websocket connectivity and token-based authentication with automatic refresh. A matching `custom_components/loxws` package provides a config flow, coordinator-based refresh, and connection lifecycle management aligned with the current Home Assistant architecture guidelines.
