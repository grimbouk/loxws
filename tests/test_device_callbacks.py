"""Unit tests for device callback registration and value handling."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "loxws")))

from loxcolorpickerv2 import LoxColorPickerV2
from loxiroomcontrollerv2 import LoxIntelligentRoomControllerV2
from loxswitch import LoxSwitch


class TestDeviceCallbacks(unittest.TestCase):
    """Verify callbacks are registered and removed correctly."""

    def test_switch_unregister_stops_callback_notifications(self):
        device = LoxSwitch("id1", "Test", "Switch", "Room", "Cat")
        calls = []

        def _cb():
            calls.append("called")

        device.register_async_callback(_cb)
        device.set_value("active", 1)
        self.assertEqual(calls, ["called"])

        device.unregister_async_callback(_cb)
        device.set_value("active", 0)
        self.assertEqual(calls, ["called"])

    def test_colorpicker_temp_payload_updates_state(self):
        device = LoxColorPickerV2("id1", "Color", "ColorPickerV2", "Room", "Cat", {})
        device.set_value("color", "temp(50,4200)")

        self.assertTrue(device.state)
        self.assertAlmostEqual(device.brightness, 127.5)
        self.assertEqual(device.color_temp, 4200)

    def test_room_controller_unknown_enum_value_does_not_crash(self):
        device = LoxIntelligentRoomControllerV2("id1", "Climate", "IRoomControllerV2", "Room", "Cat", {})

        device.set_value("activeMode", 7)
        device.set_value("currentMode", 8)
        device.set_value("overrideReason", 12)

        self.assertEqual(device.active_mode, 7)
        self.assertEqual(device.current_mode, 8)
        self.assertEqual(device.override_reason["text"], "Unknown (12)")


if __name__ == "__main__":
    unittest.main()
