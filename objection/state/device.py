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


class Macos(Device):
    """ Represents macOS specific configurations. """

    name = 'macos'
    path_separator = '/'


class DeviceState(object):
    """ A class representing the state of a device and its runtime. """

    platform: Device
    version: str

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
        return f'<Type: {self.platform} >'


device_state = DeviceState()
