import unittest

from objection.state.device import device_state, Ios


class TestDevice(unittest.TestCase):
    def test_device_representation(self):
        device_state.device = Ios
        device_state.frida_version = '10.6.1'
        device_state.os_version = '1'

        self.assertTrue('Frida Version:10.6.1 OS Version: 1' in repr(device_state) and 'Ios' in repr(device_state))
