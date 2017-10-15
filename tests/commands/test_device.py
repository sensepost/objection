import unittest
from unittest import mock

from objection.commands.device import get_device_info, _get_ios_device_information, _get_android_device_information, \
    get_environment, _get_ios_environment, _get_android_environment
from ..helpers import capture


class TestDevice(unittest.TestCase):
    @mock.patch('objection.commands.device.FridaRunner')
    @mock.patch('objection.commands.device._get_ios_device_information')
    def test_gets_device_info_for_ios_devices(self, mock_ios_device_information, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).frida_version = mock.PropertyMock(return_value='10.0.1')
        type(mock_response).device_type = mock.PropertyMock(return_value='ios')
        mock_runner.return_value.get_last_message.return_value = mock_response

        mock_ios_device_information.return_value = ('a', 'b', 'c', 'd')

        self.assertEqual(get_device_info(), ('a', 'b', 'c', 'd'))

    @mock.patch('objection.commands.device.FridaRunner')
    @mock.patch('objection.commands.device._get_android_device_information')
    def test_gets_device_info_for_android_devices(self, mock_android_device_information, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).frida_version = mock.PropertyMock(return_value='10.0.1')
        type(mock_response).device_type = mock.PropertyMock(return_value='android')
        mock_runner.return_value.get_last_message.return_value = mock_response

        mock_android_device_information.return_value = ('a', 'b', 'c', 'd')

        self.assertEqual(get_device_info(), ('a', 'b', 'c', 'd'))

    @mock.patch('objection.commands.device.FridaRunner')
    def test_fails_to_get_device_info_if_hook_failed_to_run(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False

        mock_runner.return_value.get_last_message.return_value = mock_response

        with self.assertRaises(Exception) as _:
            with capture(get_device_info) as _:
                pass

    @mock.patch('objection.commands.device.FridaRunner')
    def test_gets_ios_device_information_from_helper_sucessfully(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).applicationName = mock.PropertyMock(return_value='a')
        type(mock_response).systemName = mock.PropertyMock(return_value='b')
        type(mock_response).model = mock.PropertyMock(return_value='c')
        type(mock_response).systemVersion = mock.PropertyMock(return_value='d')

        mock_runner.return_value.get_last_message.return_value = mock_response

        self.assertEqual(_get_ios_device_information(), ('a', 'b', 'c', 'd'))

    @mock.patch('objection.commands.device.FridaRunner')
    def test_gets_ios_device_information_from_helper_with_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False

        mock_runner.return_value.get_last_message.return_value = mock_response

        with self.assertRaises(Exception) as _:
            with capture(_get_ios_device_information) as _:
                pass

    @mock.patch('objection.commands.device.FridaRunner')
    def test_gets_android_device_information_from_helper_sucessfully(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).application_name = mock.PropertyMock(return_value='a')
        type(mock_response).device = mock.PropertyMock(return_value='b')
        type(mock_response).brand = mock.PropertyMock(return_value='c')
        type(mock_response).version = mock.PropertyMock(return_value='d')

        mock_runner.return_value.get_last_message.return_value = mock_response

        self.assertEqual(_get_android_device_information(), ('a', 'b', 'c', 'd'))

    @mock.patch('objection.commands.device.FridaRunner')
    def test_gets_android_device_information_from_helper_with_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False

        mock_runner.return_value.get_last_message.return_value = mock_response

        with self.assertRaises(Exception) as _:
            with capture(_get_android_device_information) as _:
                pass

    @mock.patch('objection.commands.device._get_ios_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_ios_platform_specific_method(self, mock_device_state, mock_ios_environment):
        type(mock_device_state).device_type = mock.PropertyMock(return_value='ios')

        get_environment()

        self.assertTrue(mock_ios_environment.called)

    @mock.patch('objection.commands.device._get_android_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_android_platform_specific_method(self, mock_device_state,
                                                                         mock_android_environment):
        type(mock_device_state).device_type = mock.PropertyMock(return_value='android')

        get_environment()

        self.assertTrue(mock_android_environment.called)

    @mock.patch('objection.commands.device.FridaRunner')
    def test_prints_ios_environment_via_platform_helpers(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = mock.PropertyMock(return_value={'foo': '/bar'})

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(_get_ios_environment) as o:
            output = o

        expected_output = """
Name    Path
------  ------
foo     /bar
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.device.FridaRunner')
    def test_prints_fail_for_ios_environment_via_platform_helpers(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(_get_ios_environment) as o:
            output = o

        expected_output = 'Failed to get environment directories.\n'

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.device.FridaRunner')
    def test_prints_android_environment_via_platform_helpers(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = mock.PropertyMock(return_value={'foo': '/bar'})

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(_get_android_environment) as o:
            output = o

        expected_output = """
Name    Path
------  ------
foo     /bar
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.device.FridaRunner')
    def test_prints_fail_for_android_environment_via_platform_helpers(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(_get_android_environment) as o:
            output = o

        expected_output = 'Failed to get environment directories.\n'

        self.assertEqual(output, expected_output)
