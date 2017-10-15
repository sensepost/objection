import unittest
from unittest import mock

from objection.commands.android.command import execute
from ...helpers import capture


class TestCommand(unittest.TestCase):
    @mock.patch('objection.commands.android.command.FridaRunner')
    def test_execute_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(execute, ['foo', 'bar', 'baz']) as o:
            output = o

        expected_output = """Running command: foo bar baz

Failed to run command with error: test
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.android.command.FridaRunner')
    def test_execute_prints_output(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).stdout = 'foobar'
        type(mock_response).stderr = 'bazfoo'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(execute, ['foo', 'bar', 'baz']) as o:
            output = o

        expected_output = """Running command: foo bar baz

foobar
bazfoo
"""

        self.assertEqual(output, expected_output)
