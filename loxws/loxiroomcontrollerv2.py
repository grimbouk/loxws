import logging

_LOGGER = logging.getLogger(__name__)

class LoxIntelligentRoomControllerV2:
    """Class for node abstraction."""

    def __init__(self, id, name, device_type, room, cat, details):
        self._id = id
        self._name = name
        self._device_type = device_type
        self._room = room
        self._cat = cat
        self._details = details

        self._active_mode = 0
        self._operating_mode = 0
        self._prepare_state = 0
        self._override_reason = 0
        self._temp_actual = 0
        self._temp_target = 0
        self._open_window = 0
        self._actual_outdoor_temp  = 0
        self._average_outdoor_temp  = 0
        self._current_mode = 0
        self._capabilities = 0

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
    def active_mode(self):
        return self._active_mode

    @property
    def operating_mode(self):
        return self._operating_mode

    @property
    def prepare_state(self):
        return self._prepare_state

    @property
    def override_reason(self):
        return self._override_reason

    @property
    def temp_actual(self):
        return self._temp_actual

    @property
    def temp_target(self):
        return self._temp_target

    @property
    def open_window(self):
        return self._open_window

    @property
    def actual_outdoor_temp(self):
        return self._actual_outdoor_temp

    @property
    def average_outdoor_temp(self):
        return self._average_outdoor_temp

    @property
    def current_mode(self):
        return self._current_mode

    @property
    def capabilities(self):
        return self._capabilities

    def register_async_callback(self, async_callback):
        #_LOGGER.debug("register_async_callback")
        self.async_callbacks.append(async_callback)

    def unregister_async_callback(self, callback):
        #_LOGGER.debug("unregister_async_callback")
        if callback in self.async_callbacks:
            self.async_callbacks.remove(callback)

    def async_update(self):
        for async_signal_update in self.async_callbacks:
            #_LOGGER.debug("id:'{0}', name:'{1}', [async_update()] ".format(self._id, self._name))
            async_signal_update()

    def set_value(self, stateName, value):
        
        if self._device_type == "IRoomControllerV2":
            switch stateName:
                case "activeMode":
                    _LOGGER.debug("id:'{0}', name:'{1}', [activeMode] - state={2}".format(self._id, self._name, value))
                    self._active_mode = value
                    self.async_update()

                case "operatingMode":
                    _LOGGER.debug("id:'{0}', name:'{1}', [operatingMode] - state={2}".format(self._id, self._name, value))
                    self._operating_mode = value
                    self.async_update()

                case "prepareState":
                    _LOGGER.debug("id:'{0}', name:'{1}', [prepareState] - state={2}".format(self._id, self._name, value))
                    self._prepare_state = value
                    self.async_update()

                case "overrideReason":
                    _LOGGER.debug("id:'{0}', name:'{1}', [overrideReason] - state={2}".format(self._id, self._name, value))
                    self._override_reason = value
                    self.async_update()

                case "tempActual":
                    _LOGGER.debug("id:'{0}', name:'{1}', [tempActual] - state={2}".format(self._id, self._name, value))
                    self._temp_actual = value
                    self.async_update()

                case "tempTarget":
                    _LOGGER.debug("id:'{0}', name:'{1}', [tempTarget] - state={2}".format(self._id, self._name, value))
                    self._temp_target = value
                    self.async_update()

                case "openWindow":
                    _LOGGER.debug("id:'{0}', name:'{1}', [openWindow] - state={2}".format(self._id, self._name, value))
                    self._open_window = value
                    self.async_update()

                case "actualOutdoorTemp":
                    _LOGGER.debug("id:'{0}', name:'{1}', [actualOutdoorTemp] - state={2}".format(self._id, self._name, value))
                    self._actual_outdoor_temp = value
                    self.async_update()

                case "averageOutdoorTemp":
                    _LOGGER.debug("id:'{0}', name:'{1}', [tempTarget] - state={2}".format(self._id, self._name, value))
                    self._average_outdoor_temp = value
                    self.async_update()

                case "currentMode":
                    _LOGGER.debug("id:'{0}', name:'{1}', [currentMode] - state={2}".format(self._id, self._name, value))
                    self._current_mode = value
                    self.async_update()

                case "capabilities":
                    _LOGGER.debug("id:'{0}', name:'{1}', [capabilities] - state={2}".format(self._id, self._name, value))
                    self._capabilities = value
                    self.async_update()

                case _:
                    _LOGGER.debug("id:'{0}', name:'{1}', [ValueNotSet {2}] - {3}={4}".format(self._id, self._name, self._device_type, stateName, value))
            
