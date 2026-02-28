class Device(object):
    """ Represents a mobile device """
    pass


class Android(Device):
    """ Represents Android specific configurations. """

    name = 'android'
    path_separator = '/'


class Ios(Device):
    """ Represents iOS specific configurations. """

    name = 'ios'
    path_separator = '/'


class Darwin(Device):
    """ Represents macOS/darwin specific configurations. """

    name = 'darwin'
    path_separator = '/'


class DeviceState(object):
    """ A class representing the state of a device and its runtime. """

    platform: Device
    version: str

    def __init__(self):
        self.platform = None
        self.version = None

    def set_version(self, v: str):
        """
            Set the running OS version

            :param v:
            :return:
        """

        self.version = v

    def set_platform(self, t: Device):
        """
            Set's the device type

            :param t:
            :return:
        """

        self.platform = t

    def __repr__(self) -> str:
        return f'<Type: {self.platform}>' if self.platform else '<Type: unknown>'


device_state = DeviceState()
