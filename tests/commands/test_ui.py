import unittest
from unittest import mock

from objection.commands.ui import alert, _alert_ios, ios_screenshot, dump_ios_ui, bypass_touchid, android_screenshot, \
    android_flag_secure
from objection.state.device import device_state, Ios
from ..helpers import capture


class TestUI(unittest.TestCase):
    def tearDown(self):
        device_state.device_type = None

    @mock.patch('objection.commands.ui._alert_ios')
    def test_alert_helper_method_proxy_calls_ios(self, mock_alert_ios):
        device_state.device_type = Ios()

        alert([])

        self.assertTrue(mock_alert_ios.called_with('objection!'))

    @mock.patch('objection.commands.ui._alert_ios')
    def test_alert_helper_method_proxy_calls_ios_custom_message(self, mock_alert_ios):
        device_state.device_type = Ios()

        alert(['foo'])

        self.assertTrue(mock_alert_ios.called_with('foo'))

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_alert_ios_helper_method(self, mock_api):
        _alert_ios('foo')

        self.assertTrue(mock_api.return_value.ios_ui_alert.called)

    def test_ios_screenshot_validates_arguments(self):
        with capture(ios_screenshot, []) as o:
            output = o

        self.assertTrue(output, 'Usage: ios ui screenshot <local png destination>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.ui.open', create=True)
    def test_ios_screenshot(self, mock_open, mock_api):
        mock_api.return_value.ios_ui_screenshot.return_value = b'\x00'

        with capture(ios_screenshot, ['foo']) as o:
            output = o

        self.assertTrue(output, 'Screenshot saved to: foo.png\n')
        self.assertTrue(mock_open.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump_ios_ui(self, mock_api):
        mock_api.return_value.ios_ui_window_dump.return_value = 'test_ui'

        with capture(dump_ios_ui, []) as o:
            output = o

        self.assertTrue(output, 'test_ui\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_bypass_touchid(self, mock_api):
        bypass_touchid()

        self.assertTrue(mock_api.return_value.ios_ui_biometrics_bypass.called)

    def test_android_screenshot_validates_arguments(self):
        with capture(android_screenshot, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android ui screenshot <local png destination>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.ui.open', create=True)
    def test_android_screenshot(self, mock_open, mock_api):
        mock_api.return_value.android_ui_screenshot.return_value = b'\x00'

        with capture(android_screenshot, ['foo']) as o:
            output = o

        self.assertTrue(output, 'Screenshot saved to: foo.png\n')
        self.assertTrue(mock_open.called)

    def test_android_flag_secure_validates_argument_as_boolean_string(self):
        with capture(android_flag_secure, ['foo']) as o:
            output = o

        self.assertEqual(output, 'Usage: android ui FLAG_SECURE <true/false>\n')

    def test_android_flag_secure_validates_argument_is_present(self):
        with capture(android_flag_secure, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android ui FLAG_SECURE <true/false>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_android_flag_secure(self, mock_api):
        android_flag_secure(['true'])

        self.assertTrue(mock_api.return_value.android_ui_set_flag_secure.called)
