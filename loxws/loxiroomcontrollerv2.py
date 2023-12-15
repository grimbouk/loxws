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
        self._demand = 0
        self._comfort_temperature = 0
        self._comfort_temperature_cool = 0

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

    @property
    def demand(self):
        return self._demand

    @property
    def comfort_temperature(self):
        return self._comfort_temperature

    @property
    def comfort_temperature_cool(self):
        return self._comfort_temperature_cool

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
        if self._device_type == "IRoomControllerV2" and stateName == "activeMode":
            value = int(value)
            value_names = ["0 = Economy","1 = Comfort temperature","2 = Building protection","3 = Manual"]
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}, hint:'{4}'".format(self._id, self._name, stateName, value, value_names[value]))
            self._active_mode = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "operatingMode":
            value = int(value)
            value_names = ["0 = Automatic, heating and cooling allowed","1 = Automatic, only heating allowed","2 = Automatic, only cooling allowed","3 = Manual, heating and cooling allowed","4 = Manual, only heating allowed","5 = Manual, only cooling allowed"]
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}, hint:'{4}'".format(self._id, self._name, stateName, value, value_names[value]))
            self._operating_mode = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "prepareState":
            value = int(value)
            value_names = ["-1 = Cooling down","0 = No Action","1 = Heating up"]
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}, hint:'{4}'".format(self._id, self._name, stateName, value, value_names[value + 1]))
            self._prepare_state = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "overrideReason":
            value = int(value)
            value_names = ["0 = None","1 = Someone is present -> Comfort mode is active","2 = Window open -> Eco+ mode is active","3 = Comfort overrid","4 = Eco override","Eco+ override","6 = Prepare State Heat Up","7 = Prepare State Cool Down","8 = Overriden by source (source needs demand)"]
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}, hint:'{4}'".format(self._id, self._name, stateName, value, value_names[value]))
            self._override_reason = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "tempActual":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._temp_actual = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "tempTarget":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._temp_target = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "openWindow":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._open_window = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "actualOutdoorTemp":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._actual_outdoor_temp = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "averageOutdoorTemp":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._average_outdoor_temp = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "currentMode":
            value = int(value)
            value_names = ["0 = Automatic, heating and cooling allowed","1 = Automatic, only heating allowed","2 = Automatic, only cooling allowed","3 = Manual, heating and cooling allowed","4 = Manual, only heating allowed","5 = Manual, only cooling allowed"]
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}, hint:'{4}'".format(self._id, self._name, stateName, value, value_names[value]))
            self._current_mode = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "capabilities":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._capabilities = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "demand":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._demand = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "comfortTemperature":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._comfort_temperature = value
            self.async_update()

        elif self._device_type == "IRoomControllerV2" and stateName == "comfortTemperatureCool":
            _LOGGER.debug("id:'{0}', name:'{1}', state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
            self._comfort_temperature_cool = value
            self.async_update()

        else:
            _LOGGER.debug("id:'{0}', name:'{1}', unknown state:'{2}', value:{3}".format(self._id, self._name, stateName, value))
    
