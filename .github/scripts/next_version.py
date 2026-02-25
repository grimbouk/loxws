#!/usr/bin/env python3
"""Compute next 0.0.N version for loxws."""

import json
import re
import sys
import urllib.request
from pathlib import Path


PROJECT = "loxws"
LOCAL_VERSION_FILE = Path("loxws/_version.py")


def local_patch_version() -> int:
    text = LOCAL_VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"0\.0\.(\d+)"', text)
    if not match:
        return 0
    return int(match.group(1))


def pypi_patch_version() -> int:
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{PROJECT}/json", timeout=20
        ) as response:
            data = json.load(response)
    except Exception as exc:
        print(
            f"Warning: failed to query PyPI ({exc}); using local version baseline.",
            file=sys.stderr,
        )
        return 0

    max_patch = 0
    for version in data.get("releases", {}):
        match = re.fullmatch(r"0\.0\.(\d+)", version)
        if match:
            max_patch = max(max_patch, int(match.group(1)))
    return max_patch


def main() -> int:
    next_patch = max(local_patch_version(), pypi_patch_version()) + 1
    print(f"0.0.{next_patch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
