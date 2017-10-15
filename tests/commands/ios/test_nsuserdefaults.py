import unittest
from unittest import mock

from objection.commands.ios.nsuserdefaults import get
from ...helpers import capture


class TestNsuserdefaults(unittest.TestCase):
    @mock.patch('objection.commands.ios.nsuserdefaults.FridaRunner')
    def test_get_handles_hook_errors(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'Failed to get nsuserdefaults with error: test\n')

    @mock.patch('objection.commands.ios.nsuserdefaults.FridaRunner')
    def test_get(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = 'foo'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'foo\n')
