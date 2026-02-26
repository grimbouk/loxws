"""Unit tests for device callback registration and value handling."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "loxws")))

from loxcolorpickerv2 import LoxColorPickerV2
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


if __name__ == "__main__":
    unittest.main()
