import logging

from .loxdimmer import LoxDimmer
from .loxswitch import LoxSwitch
from .loxcolorpickerv2 import LoxColorPickerV2
from .loxlightcontrollerv2 import LoxLightControllerV2
from .loxiroomcontrollerv2 import LoxIntelligentRoomControllerV2
from .loxinfoonlyanalog import LoxInfoOnlyAnalog
from .loxinfoonlydigital import LoxInfoOnlyDigital
from .loxclimatecontroller import LoxClimateController
from .loxjalousie import LoxJalousie
from .loxpresencedetector import LoxPresenceDetector
from .loxalarmclock import LoxAlarmClock
from .loxwindow import LoxWindow
from .loxgate import LoxGate
from .loxmeter import LoxMeter

_LOGGER = logging.getLogger(__name__)

class ConfigData:
    """Class for config data."""

    def __init__(self, rawdata):
        """Initialize config data object."""
        self.data = rawdata
        self.fieldmap = {}
        self.devices = {}
        self.scenes = {}
        self.sensors = {}
        self.binarysensors = {}
        self.covers = {}
        self.roomcontrollers = {}
        self.climatecontrollers = {}
        self.meters = {}
        self.presencedetectors = {}
        self.alarmclocks = {}
        self.gates = {}
        self.switches = {}
        self.windows = {}

        try:
            for k,v in self.data["controls"].items():
                roomName = ''
                if 'room' in v:
                    roomName = self.get_room_name(v["room"])

                catName = ''
                if 'cat' in v:
                    catName = self.get_cat_name(v["cat"])

                if v["type"] == 'Jalousie':
                    self.covers[k] = LoxJalousie(k, v["name"], v["type"], roomName, catName, v["details"])
                    _LOGGER.debug("  Map states for Jalousie")
                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.covers[k], "stateName": tk}

                if v["type"] == 'ClimateController':
                    self.climatecontrollers[k] = LoxClimateController(k, v["name"], v["type"], roomName, catName, v["details"])
                    
                    #_LOGGER.debug("  Map ClimateController {0}".format(k))
                    #self.fieldmap[k] = {"device": self.climatecontrollers[k], "stateName": tk}

                    _LOGGER.debug("  Map states for ClimateController")
                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.climatecontrollers[k], "stateName": tk}

                if v["type"] == 'LightControllerV2':
                    self.scenes[k] = LoxLightControllerV2(k, v["name"], v["type"], roomName, catName, v["details"])
                    _LOGGER.debug("  Map states for LightControllerV2")
                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.scenes[k], "stateName": tk}

                if v["type"] == 'IRoomControllerV2':
                    self.roomcontrollers[k] = LoxIntelligentRoomControllerV2(k, v["name"], v["type"], roomName, catName, v["details"])
                    _LOGGER.debug("  Map states for IRoomControllerV2")
                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.roomcontrollers[k], "stateName": tk}

                if v["type"] == 'InfoOnlyAnalog':
                    _LOGGER.debug("  InfoOnlyAnalog - {0}".format(k))
                    self.sensors[k] = LoxInfoOnlyAnalog(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.sensors[k], "stateName": tk}

                if v["type"] == 'InfoOnlyDigital':
                    self.binarysensors[k] = LoxInfoOnlyDigital(k, v["name"], v["type"], roomName, catName, v["details"])
                    _LOGGER.debug("  Map states for InfoOnlyDigital")
                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.binarysensors[k], "stateName": tk}

                if v["type"] == 'LightControllerV2' and 'subControls' in v:
                    for sk,sv in v["subControls"].items():
                        _LOGGER.debug("  Adding Light: {0} {1}".format(sk, sv["name"]))
                        if sv["type"] == 'Switch':
                            self.devices[sk] = LoxSwitch(sk, sv["name"], sv["type"], roomName, catName)
                        elif sv["type"] == 'Dimmer':
                            self.devices[sk] = LoxDimmer(sk, sv["name"], sv["type"], roomName, catName)
                        elif sv["type"] == 'ColorPickerV2':
                            self.devices[sk] = LoxColorPickerV2(sk, sv["name"], sv["type"], roomName, catName, sv["details"])

                        _LOGGER.debug("  Map states for Light")
                        for stk,stv in sv["states"].items():
                            _LOGGER.debug("    state: {0} = {1}".format(stv, stk))
                            self.fieldmap[stv] = {"device": self.devices[sk], "stateName": stk}

                if v["type"] == 'Meter':
                    _LOGGER.debug("  Meter - {0}".format(k))
                    self.meters[k] = LoxMeter(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.meters[k], "stateName": tk}

                if v["type"] == 'PresenceDetector':
                    _LOGGER.debug("  PresenceDetector - {0}".format(k))
                    self.presencedetectors[k] = LoxPresenceDetector(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.presencedetectors[k], "stateName": tk}

                if v["type"] == 'AlarmClock':
                    _LOGGER.debug("  AlarmClock - {0}".format(k))
                    self.alarmclocks[k] = LoxAlarmClock(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.alarmclocks[k], "stateName": tk}

                if v["type"] == 'Gate':
                    _LOGGER.debug("  Gate - {0}".format(k))
                    self.gates[k] = LoxGate(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.gates[k], "stateName": tk}

                if v["type"] == 'Switch':
                    _LOGGER.debug("  Switch - {0}".format(k))
                    self.switches[k] = LoxSwitch(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.switches[k], "stateName": tk}

                if v["type"] == 'TimedSwitch':
                    _LOGGER.debug("  TimedSwitch - {0}".format(k))
                    self.switches[k] = LoxSwitch(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.switches[k], "stateName": tk}

                if v["type"] == 'Window':
                    _LOGGER.debug("  Window - {0}".format(k))
                    self.windows[k] = LoxWindow(k, v["name"], v["type"], roomName, catName, v["details"])

                    for tk,tv in v["states"].items():
                        _LOGGER.debug("    state: {0} = {1}".format(tv, tk))
                        self.fieldmap[tv] = {"device": self.windows[k], "stateName": tk}

#IRCV2Daytimer
#Daytimer
#Tracker

        except Exception as ex:
            _LOGGER.error(ex)
            
        _LOGGER.debug("Config Done")

    def get_room_name(self, uuid):
        for k,v in self.data["rooms"].items():
            if k == uuid:
                return v["name"]
        return ''

    def get_cat_name(self, uuid):
        for k,v in self.data["cats"].items():
            if k == uuid:
                return v["name"]
        return ''
