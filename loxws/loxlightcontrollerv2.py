import logging

_LOGGER = logging.getLogger(__name__)

class LoxLightControllerV2:
    """Class for LightControllerV2 abstraction."""

    def __init__(self, id, name, device_type, room, cat, details):
        #_LOGGER.debug("{0} init".format(id))
        self._id = id
        self._name = name
        self._device_type = device_type
        self._room = room
        self._cat = cat
        self._details = details
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
        #_LOGGER.debug("{0} cat={1}".format(self._id, self._cat))
        return self._cat

    @property
    def details(self):
        return self._details


    @property
    def manufacturer_name(self):
        #_LOGGER.debug("{0} manufacturer_name={1}".format(self._id, 'Loxone'))
        return 'Loxone'    

    def register_async_callback(self, async_callback):
        #_LOGGER.debug("{0} register_async_callback".format(self._id))
        self.async_callbacks.append(async_callback)

    def unregister_async_callback(self, callback):
        #_LOGGER.debug("{0} unregister_async_callback".format(self._id))
        if callback in self.async_callbacks:
            self.async_callbacks.remove(callback)

    def async_update(self):
        for async_signal_update in self.async_callbacks:
            async_signal_update()


    def set_value(self, stateName, value):
        if self._device_type == "LightControllerV2" and stateName == "moodList":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
            #device.add_modes(value)

        else:
            _LOGGER.debug("id:'{0}', name:'{1}', [ValueNotSet {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
