import unittest

from objection.state.connection import state_connection


class TestConnection(unittest.TestCase):
    def setUp(self):
        pass

    def test_default_type_is_usb(self):
        comms_type = state_connection.get_comms_type()
        comms_type_string = state_connection.get_comms_type_string()

        self.assertEqual(comms_type, 0)
        self.assertEqual(comms_type_string, 'usb')

    def test_sets_type_to_network(self):
        state_connection.use_network()

        comms_type = state_connection.get_comms_type()
        comms_type_string = state_connection.get_comms_type_string()

        self.assertEqual(comms_type, 1)
        self.assertEqual(comms_type_string, 'net')

    def test_sets_type_usb_after_setting_type_network(self):
        state_connection.use_network()
        state_connection.use_usb()

        comms_type = state_connection.get_comms_type()
        comms_type_string = state_connection.get_comms_type_string()

        self.assertEqual(comms_type, 0)
        self.assertEqual(comms_type_string, 'usb')
