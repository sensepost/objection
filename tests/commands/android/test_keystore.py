import unittest
from unittest import mock

from objection.commands.android.keystore import entries, clear
from ...helpers import capture


class TestKeystore(unittest.TestCase):
    @mock.patch('objection.commands.android.keystore.FridaRunner')
    def test_entries_handles_hook_errors(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(entries, []) as o:
            output = o

        self.assertEqual(output, 'Failed to list KeyStore items with error: test\n')

    @mock.patch('objection.commands.android.keystore.FridaRunner')
    def test_entries_handles_empty_data(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = None

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(entries, []) as o:
            output = o

        self.assertEqual(output, 'No keystore items were found\n')

    @mock.patch('objection.commands.android.keystore.FridaRunner')
    def test_entries_handles(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = [{
            'alias': 'test',
            'is_key': True,
            'is_certificate': True
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(entries, []) as o:
            output = o

        expected_output = """Alias    Is Key    Is Certificate
-------  --------  ----------------
test     True      True
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.android.keystore.FridaRunner')
    def test_clear_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Failed to clear the KeyStore error: test\n')

    @mock.patch('objection.commands.android.keystore.FridaRunner')
    def test_clear(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Cleared the KeyStore\n')
