import logging

_LOGGER = logging.getLogger(__name__)

class LoxInfoOnlyDigital:
    """Class for node abstraction."""

    def __init__(self, id, name, device_type, room, cat, details):
        self._id = id
        self._name = name
        self._device_type = device_type
        self._room = room
        self._cat = cat
        self._details = details
        self._state = False
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
        return self._room

    @property
    def category(self):
        return self._cat

    @property
    def details(self):
        return self._details


    @property
    def manufacturer_name(self):
        return 'Loxone'    

    @property
    def state(self):
        return self._state

    @property
    def format(self):
        return ""

    def register_async_callback(self, async_callback):
        #_LOGGER.debug("register_async_callback")
        self.async_callbacks.append(async_callback)

    def unregister_async_callback(self, callback):
        #_LOGGER.debug("unregister_async_callback")
        if callback in self.async_callbacks:
            self.async_callbacks.remove(callback)

    def async_update(self):
        for async_signal_update in self.async_callbacks:
            #_LOGGER.debug("id:'{0}', name:'{1}', [async_update()] state={2}".format(self._id, self._name, self._state))
            async_signal_update()

    def set_value(self, stateName, value):
        if self._device_type == "InfoOnlyDigital" and stateName == "active":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue InfoOnlyDigital] - state={2}".format(self._id, self._name, value))

            if value > 0:
                self._state = self._details["text"]["on"]
            else:
                self._state = self._details["text"]["off"]

            self.async_update()

        else:
            _LOGGER.debug("id:'{0}', name:'{1}', [ValueNotSet {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
