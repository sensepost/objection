class Device(object):
    """ Represents a mobile device """
    pass


class Android(Device):
    """ Represents Android specific configurations. """

    name = 'android'
    path_seperator = '/'


class Ios(Device):
    """ Represents iOS specific configurations. """
   
    name = 'ios'
    path_seperator = '/'


class DeviceState(object):
    """ A class representing the state of a device and its runtime. """

    def __init__(self) -> None:
        self.device = None
        self.frida_version = None
        self.os_version = None

    def __repr__(self) -> str:
        return '<Type: {0} Frida Version:{1} OS Version: {2}>'.format(self.device, self.frida_version,
                                                                      self.os_version)


device_state = DeviceState()
