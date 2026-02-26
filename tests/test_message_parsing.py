"""Unit tests for websocket binary message parsing."""

from __future__ import annotations

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "loxws")))

from messagebody import MessageBody
from messageheader import MessageHeader


def uuid_to_lox_bytes(uuid_str: str) -> bytes:
    """Encode Loxone UUID string (8-4-4-16) to little-endian bytes."""
    p1, p2, p3, p4 = uuid_str.split("-")
    return (
        int(p1, 16).to_bytes(4, "little")
        + int(p2, 16).to_bytes(2, "little")
        + int(p3, 16).to_bytes(2, "little")
        + bytes.fromhex(p4)
    )


class _FakeDevice:
    def __init__(self):
        self.id = "dev1"
        self.name = "Device"
        self.device_type = "Switch"
        self.updates = []

    def set_value(self, state_name, value):
        self.updates.append((state_name, value))


class _FakeConfig:
    def __init__(self, fieldmap):
        self.fieldmap = fieldmap


class _FakeHeader:
    def __init__(self, msg_type):
        self.msg_type = msg_type


class TestMessageParsing(unittest.TestCase):
    """Validate parser behavior for mapped state updates."""

    def test_message_header_mapping(self):
        header = MessageHeader(bytes([3, 2, 0, 0, 0, 0, 0, 0]))
        self.assertEqual(header.msg_type, "Value-States")

    def test_value_states_updates_mapped_device(self):
        uuid_str = "00112233-4455-6677-8899aabbccddeeff"
        device = _FakeDevice()
        cfg = _FakeConfig({uuid_str: {"device": device, "stateName": "active"}})

        payload = uuid_to_lox_bytes(uuid_str) + struct.pack("<d", 1.0)
        MessageBody(payload, True, _FakeHeader("Value-States"), cfg)

        self.assertEqual(device.updates, [("active", 1.0)])

    def test_text_states_updates_mapped_device(self):
        uuid_str = "00112233-4455-6677-8899aabbccddeeff"
        icon_uuid = "00000000-0000-0000-0000000000000000"
        text_value = "hsv(12,34,56)"

        device = _FakeDevice()
        cfg = _FakeConfig({uuid_str: {"device": device, "stateName": "color"}})

        text_bytes = text_value.encode("utf-8")
        size = len(text_bytes)
        padding = b"\x00" * ((4 - (size % 4)) % 4)
        payload = (
            uuid_to_lox_bytes(uuid_str)
            + uuid_to_lox_bytes(icon_uuid)
            + struct.pack("<I", size)
            + text_bytes
            + padding
        )
        MessageBody(payload, True, _FakeHeader("Text-States"), cfg)

        self.assertEqual(device.updates, [("color", text_value)])


if __name__ == "__main__":
    unittest.main()
