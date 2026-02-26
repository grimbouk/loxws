"""Simple command-line connectivity runner for loxws."""

from __future__ import annotations

import argparse
import asyncio
import logging

from loxws import Miniserver

_LOGGER = logging.getLogger(__name__)


def _build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Connect to a Loxone Miniserver via loxws")
    parser.add_argument("--host", required=True, help="Miniserver host/IP")
    parser.add_argument("--port", type=int, default=443, help="Miniserver port")
    parser.add_argument("--username", required=True, help="Loxone username")
    parser.add_argument("--password", required=True, help="Loxone password")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to wait for readiness")
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates (off by default for local/self-signed setups)",
    )
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    ready_event = asyncio.Event()

    def _on_connection_status(available: bool) -> None:
        if available:
            ready_event.set()

    loop = asyncio.get_running_loop()
    miniserver = Miniserver(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        use_tls=True,
        verify_tls=args.verify_tls,
    )

    try:
        miniserver.connect(loop, _on_connection_status)
        await miniserver.wait_until_ready(timeout=args.timeout)
        await ready_event.wait()
        _LOGGER.info("Connection ready")
        return 0
    finally:
        miniserver.shutdown()


def main() -> int:
    args = _build_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        _LOGGER.info("Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
