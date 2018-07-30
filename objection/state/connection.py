class StateConnection(object):
    """ A class controlling the connection state of a device. """

    TYPE_USB = 0
    TYPE_REMOTE = 1

    def __init__(self) -> None:
        """
            Init a new connection state, defaulting to a USB
            connection.
        """

        self.usb = True
        self.network = False
        self.host = '127.0.0.1'
        self.port = 27042
        self._type = self.TYPE_USB
        self.device_serial = None

        self.gadget_name = 'Gadget'
        self.agent = None
        self.api = None

    def use_usb(self) -> None:
        """
            Sets the values required to have a USB connection.

            :return:
        """

        self.network = False
        self.usb = True
        self._type = self.TYPE_USB

    def use_network(self) -> None:
        """
            Sets the values required to have a Network connection.

            :return:
        """

        self.network = True
        self.usb = False
        self._type = self.TYPE_REMOTE

    def get_comms_type(self) -> int:
        """
            Returns the currently configured connection type.

            :return:
        """

        return self._type

    def get_comms_type_string(self) -> str:
        """
            Returns the currently configured connection type as a string.

            :return:
        """

        t = self.get_comms_type()

        if t == self.TYPE_USB:
            return 'usb'

        if t == self.TYPE_REMOTE:
            return 'net'

        return ''

    def get_api(self):
        """
            Return a Frida RPC API session

            :return:
        """

        if not self.agent:
            raise Exception('No session available to get API')

        return self.agent.exports()

    def set_agent(self, agent):
        """
            Sets the active agent to use for communications.

            :param agent:
            :return:
        """

        self.agent = agent

    def get_agent(self):

        if not self.agent:
            raise Exception('No Agent available')

        return self.agent

    def __repr__(self) -> str:
        return '<State Usb:{0}, Network:{1}, Host:{2}, Port:{3}'.format(self.usb, self.network, self.host, self.port)


state_connection = StateConnection()
