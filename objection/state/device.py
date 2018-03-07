class DeviceState(object):
    """ A class representing the state of a device and its runtime. """

    def __init__(self) -> None:
        self.device_type = None
        self.frida_version = None
        self.os_version = None

    def __repr__(self) -> str:
        return '<Type: {0} Frida Version:{1} OS Version: {2}>'.format(self.device_type, self.frida_version, self.os_version)


device_state = DeviceState()
