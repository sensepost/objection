import unittest
from unittest import mock

from objection.commands.ui import alert, _alert_ios, ios_screenshot, dump_ios_ui, bypass_touchid, android_screenshot, \
    android_flag_secure
from objection.state.device import device_state
from ..helpers import capture


class TestUI(unittest.TestCase):
    def tearDown(self):
        device_state.device_type = None

    @mock.patch('objection.commands.ui._alert_ios')
    def test_alert_helper_method_proxy_calls_ios(self, mock_alert_ios):
        device_state.device_type = 'ios'

        alert([])

        self.assertTrue(mock_alert_ios.called_with('objection!'))

    @mock.patch('objection.commands.ui._alert_ios')
    def test_alert_helper_method_proxy_calls_ios_custom_message(self, mock_alert_ios):
        device_state.device_type = 'ios'

        alert(['foo'])

        self.assertTrue(mock_alert_ios.called_with('foo'))

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_alert_ios_helper_method(self, mock_runner):
        _alert_ios('foo')

        self.assertTrue(mock_runner.return_value.set_hook_with_data.called)
        self.assertTrue(mock_runner.return_value.run.called)

    def test_ios_screenshot_validates_arguments(self):
        with capture(ios_screenshot, []) as o:
            output = o

        self.assertTrue(output, 'Usage: ios ui screenshot <local png destination>\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_ios_screenshot_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_message = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(ios_screenshot, ['foo']) as o:
            output = o

        self.assertTrue(output, 'Failed to screenshot with error: test\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    @mock.patch('objection.commands.ui.open', create=True)
    def test_ios_screenshot(self, mock_open, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        mock_response.get_extra_data.return_value = 'image_data'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(ios_screenshot, ['foo']) as o:
            output = o

        self.assertTrue(output, 'Screenshot saved to: foo.png\n')
        self.assertTrue(mock_open.called)

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_dump_ios_ui_handles_failed_hook(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_message = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump_ios_ui, []) as o:
            output = o

        self.assertTrue(output, 'Failed to dump UI with error: test\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_dump_ios_ui(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = 'test_ui'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump_ios_ui, []) as o:
            output = o

        self.assertTrue(output, 'test_ui\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_bypass_touchid(self, mock_runner):
        bypass_touchid()

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    def test_android_screenshot_validates_arguments(self):
        with capture(android_screenshot, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android ui screenshot <local png destination>\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    @mock.patch('objection.commands.ui.open', create=True)
    def test_android_screenshot_fails_with_empty_data(self, mock_open, mock_runner):
        mock_api = mock.Mock()
        mock_api.screenshot.return_value = None

        mock_runner.return_value.rpc_exports.return_value = mock_api

        with capture(android_screenshot, ['foo']) as o:
            output = o

        self.assertTrue(output, 'Failed to take screenshot\n')
        self.assertFalse(mock_open.called)

    @mock.patch('objection.commands.ui.FridaRunner')
    @mock.patch('objection.commands.ui.open', create=True)
    def test_android_screenshot(self, mock_open, mock_runner):
        mock_api = mock.Mock()
        mock_api.screenshot.return_value = b'\x00'

        mock_runner.return_value.rpc_exports.return_value = mock_api

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

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_android_flag_secure(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(android_flag_secure, ['true']) as o:
            output = o

        self.assertEqual(output, 'Successfuly set FLAG_SECURE\n')

    @mock.patch('objection.commands.ui.FridaRunner')
    def test_android_flag_secure_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_message = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(android_flag_secure, ['true']) as o:
            output = o

        self.assertEqual(output, 'Failed to set FLAG_SECURE: test\n')
