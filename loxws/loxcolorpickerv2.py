import logging

_LOGGER = logging.getLogger(__name__)

class LoxColorPickerV2:
    """Class for node abstraction."""

    def __init__(self, id, name, device_type, room, cat, details):
        #_LOGGER.debug("{0} init".format(id))
        self._id = id
        self._name = name
        self._device_type = device_type
        self._room = room
        self._cat = cat
        self._details = details
        self._state = False
        self._brightness = 0
        self._color_temp = None
        self._hs_color = [0,0]
        self.async_callbacks = []
            
    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._room + " " + self._name

    @property
    def device_type(self):
        return self._device_type

    @property
    def room(self):
        #_LOGGER.debug("{0} room={1}".format(self._id, self._room))
        return self._room

    @property
    def category(self):
        return self._cat

    @property
    def details(self):
        return self._details

    @property
    def manufacturer_name(self):
        #_LOGGER.debug("{0} manufacturer_name={1}".format(self._id, 'Loxone'))
        return 'Loxone'    

    @property
    def state(self):
        return self._state

    @property
    def brightness(self):
        return self._brightness

    @property
    def color_temp(self):
        return self._color_temp

    @property
    def hs_color(self):
        return self._hs_color

    def register_async_callback(self, async_callback):
        #_LOGGER.debug("register_async_callback")
        self.async_callbacks.append(async_callback)

    def unregister_async_callback(self, callback):
        #_LOGGER.debug("unregister_async_callback")
        if callback in self.async_callbacks:
            self.async_callbacks.remove(callback)

    def async_update(self):

        for async_signal_update in self.async_callbacks:
            #_LOGGER.debug("  doing update callback")
            async_signal_update()

    def set_value(self, stateName, value):
        if self._device_type == "ColorPickerV2" and stateName == "color":
            _LOGGER.debug("id:'{0}', name:'{1}', [Set ColorPickerV2] - color={2}".format(self._id, self._name, value))

            if value.startswith("hsv"):
                #hsv(0,0,100)
                hsv = value.strip("hsv()").split(",")
                #_LOGGER.debug("  hsv: {0} {1}".format(value, hsv))
                self._brightness = int(hsv[2]) * 2.55
                self._hs_color = [ float(hsv[0]), float(hsv[1]) ]

                if self._brightness > 0:
                    self._state = True
                else:
                    self._state = False

            elif value.startswith("temp"):
                #temp(100,4783)
                temp = value.strip("temp()").split(",")
                if len(temp) >= 2:
                    brightness_pct = float(temp[0])
                    kelvin = float(temp[1])
                    self._brightness = brightness_pct * 2.55
                    self._color_temp = kelvin
                    self._state = self._brightness > 0

            #_LOGGER.debug("Update ColorPickerV2: {0}".format(self._name))
            self.async_update()
        elif self._device_type == "LightControllerV2" and stateName == "moodList":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
            #device.add_modes(value)

        else:
            _LOGGER.debug("id:'{0}', name:'{1}', [ValueNotSet {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
