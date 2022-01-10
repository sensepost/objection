class StateConnection(object):
    """ A class controlling the connection state of a device. """

    def __init__(self) -> None:
        """
            Init a new connection state, defaulting to a USB
            connection.
        """

        self.network = False
        self.host = None
        self.port = None
        self.device_type = 'usb'
        self.device_id = None

        self.spawn = False
        self.no_pause = False
        self.foremost = False
        self.debugger = False

        self.name = None
        self.agent = None
        self.api = None

    def use_usb(self) -> None:
        """
            Sets the values required to have a USB connection.

            :return:
        """

        self.network = False
        self.device_type = 'usb'

    def use_network(self) -> None:
        """
            Sets the values required to have a Network connection.

            :return:
        """

        self.network = True
        self.device_type = 'remote'

    def get_comms_type(self) -> int:
        """
            Returns the currently configured connection type.

            :return:
        """

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
        return f'<State DevSerial: {self.device_id}, Network:{self.network}, Host:{self.host}, Port:{self.port}'


state_connection = StateConnection()
