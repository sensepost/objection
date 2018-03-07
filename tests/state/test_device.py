import unittest

from objection.state.device import device_state


class TestDevice(unittest.TestCase):
    def test_device_representation(self):
        device_state.device_type = 'ios'
        device_state.frida_version = '10.6.1'
        device_state.os_version = '1'

        self.assertEqual(repr(device_state), '<Type: ios Frida Version:10.6.1 OS Version: 1>')
