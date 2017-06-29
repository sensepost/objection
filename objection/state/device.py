class DeviceState(object):
    def __init__(self):
        self.device_type = None
        self.frida_version = None

    def __repr__(self):
        return '<Type: {0} Frida Version:{1}>'.format(self.device_type, self.frida_version)


device_state = DeviceState()
