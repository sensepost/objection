class StateConnection(object):
    TYPE_USB = 0
    TYPE_REMOTE = 1

    def __init__(self):
        self.usb = True
        self.network = False
        self.host = '127.0.0.1'
        self.port = 27042
        self._type = self.TYPE_USB

        self.gadget_name = 'Gadget'

    def use_usb(self):
        self.network = False
        self.usb = True
        self._type = self.TYPE_USB

    def use_network(self):
        self.network = True
        self.usb = False
        self._type = self.TYPE_REMOTE

    def get_comms_type(self):
        return self._type

    def get_comms_type_string(self):
        t = self.get_comms_type()

        if t == self.TYPE_USB:
            return 'usb'
        if t == self.TYPE_REMOTE:
            return 'net'

        return ''

    def __repr__(self):
        return '<State Usb:{0}, Network:{1}, Host:{2}, Port:{3}'.format(self.usb, self.network, self.host, self.port)


state_connection = StateConnection()
