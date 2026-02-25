import logging

_LOGGER = logging.getLogger(__name__)

class LoxJalousie:
    """Class for node abstraction."""

    def __init__(self, id, name, device_type, room, cat, details):
        self._id = id
        self._name = name
        self._device_type = device_type
        self._room = room
        self._cat = cat
        self._details = details
        self._position = 0.0
        self._up = 0
        self._down = 0
        self._target_position = 0.0
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
    def position(self):
        return self._position

    @property
    def up(self):
        return self._up

    @property
    def down(self):
        return self._down

    @property
    def target_position(self):
        return self._target_position

    @property
    def is_opening(self):
        return bool(self._up)

    @property
    def is_closing(self):
        return bool(self._down)

    def register_async_callback(self, async_callback):
        #_LOGGER.debug("register_async_callback")
        self.async_callbacks.append(async_callback)

    def unregister_async_callback(self, callback):
        #_LOGGER.debug("unregister_async_callback")
        if callback in self.async_callbacks:
            self.async_callbacks.remove(callback)

    #def async_set_position(self, position):
    #    _LOGGER.debug("{0} [{1}] async_set_position() position={2}".format(self._id, self._name, position))

    #def async_stop(self):
    #    _LOGGER.debug("{0} [{1}] async_stop()".format(self._id, self._name))

    def async_update(self):
        for async_signal_update in self.async_callbacks:
            #_LOGGER.debug("id:'{0}', name:'{1}', [async_update()] state={2}".format(self._id, self._name, self._position))
            async_signal_update()

    def set_value(self, stateName, value):
        if self._device_type == "Jalousie" and stateName == "position":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue Jalousie] - state={2}".format(self._id, self._name, value))

            self._position = value

            self.async_update()
        elif self._device_type == "Jalousie" and stateName == "up":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue Jalousie] - up={2}".format(self._id, self._name, value))
            self._up = int(value)
            self.async_update()
        elif self._device_type == "Jalousie" and stateName == "down":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue Jalousie] - down={2}".format(self._id, self._name, value))
            self._down = int(value)
            self.async_update()
        elif self._device_type == "Jalousie" and stateName == "targetPosition":
            _LOGGER.debug("id:'{0}', name:'{1}', [SetValue Jalousie] - targetPosition={2}".format(self._id, self._name, value))
            self._target_position = float(value)
            self.async_update()

        else:
            _LOGGER.debug("id:'{0}', name:'{1}', [ValueNotSet {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
