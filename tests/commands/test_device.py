import unittest
from unittest import mock

from objection.commands.device import get_environment, _get_ios_environment, _get_android_environment
from objection.state.device import Android, Ios
from ..helpers import capture


class TestDevice(unittest.TestCase):

    @mock.patch('objection.commands.device._get_ios_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_ios_platform_specific_method(self, mock_device_state, mock_ios_environment):
        type(mock_device_state).platform = mock.PropertyMock(return_value=Ios)

        get_environment()

        self.assertTrue(mock_ios_environment.called)

    @mock.patch('objection.commands.device._get_android_environment')
    @mock.patch('objection.commands.device.device_state')
    def test_gets_environment_and_calls_android_platform_specific_method(self, mock_device_state,
                                                                         mock_android_environment):
        type(mock_device_state).platform = mock.PropertyMock(return_value=Android)

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
