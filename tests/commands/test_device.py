import unittest
from unittest import mock

from objection.commands.device import get_device_info, get_environment, _get_ios_environment, _get_android_environment
from objection.state.device import Android, Ios
from ..helpers import capture


class TestDevice(unittest.TestCase):

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_gets_ios_device_info(self, mock_api):
        mock_api.return_value.env_runtime.return_value = 'ios'
        mock_api.return_value.env_ios.return_value = {'applicationName': 'za.sensepost.ipewpew',
                                                      'deviceName': 'skdw',
                                                      'identifierForVendor': 'A549BC3C-ADA7-49D4-8B3C-A22187F461F5',
                                                      'model': 'iPhone',
                                                      'systemName': 'iOS',
                                                      'systemVersion': '11.4'}

        self.assertEqual(get_device_info(), ('za.sensepost.ipewpew', 'iOS', 'iPhone', '11.4'))

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_gets_android_device_info(self, mock_api):
        mock_api.return_value.env_runtime.return_value = 'android'
        mock_api.return_value.env_android.return_value = {'application_name': 'com.sensepost.apewpew',
                                                          'board': 'universal5422', 'brand': 'samsung',
                                                          'device': 'foobaz',
                                                          'host': 'foo.local', 'id': 'foobar', 'model': 'SM-G900H',
                                                          'product': 'k3gxx', 'user': 'jenkins', 'version': '7.1.2'}

        self.assertEqual(get_device_info(), ('com.sensepost.apewpew', 'foobaz', 'samsung', '7.1.2'))

    @mock.patch('objection.commands.device._get_ios_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_ios_platform_specific_method(self, mock_device_state, mock_ios_environment):
        type(mock_device_state).device_type = mock.PropertyMock(return_value=Ios)

        get_environment()

        self.assertTrue(mock_ios_environment.called)

    @mock.patch('objection.commands.device._get_android_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_android_platform_specific_method(self, mock_device_state,
                                                                         mock_android_environment):
        type(mock_device_state).device_type = mock.PropertyMock(return_value=Android)

        get_environment()

        self.assertTrue(mock_android_environment.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_prints_ios_environment_via_platform_helpers(self, mock_api):
        mock_api.return_value.env_ios_paths.return_value = {
            'LibraryDirectory': '/var/mobile/Containers/Data/Application/C1D04553/Library'}

        with capture(_get_ios_environment) as o:
            output = o

        expected_output = """
Name              Path
----------------  --------------------------------------------------------
LibraryDirectory  /var/mobile/Containers/Data/Application/C1D04553/Library
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_prints_android_environment_via_platform_helpers(self, mock_api):
        mock_api.return_value.env_android_paths.return_value = {
            'packageCodePath': '/data/app/com.sensepost.apewpew-1/base.apk'}

        with capture(_get_android_environment) as o:
            output = o

        expected_output = """
Name             Path
---------------  ------------------------------------------
packageCodePath  /data/app/com.sensepost.apewpew-1/base.apk
"""

        self.assertEqual(output, expected_output)
