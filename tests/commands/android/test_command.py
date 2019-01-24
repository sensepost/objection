import unittest
from unittest import mock

from objection.commands.android.command import execute
from ...helpers import capture


class TestCommand(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_execute_prints_output(self, mock_api):
        mock_api.return_value.android_shell_exec.return_value = {
            'command': 'foo bar baz', 'stdErr': 'bazfoo', 'stdOut': 'foobar\n'
        }

        with capture(execute, ['foo', 'bar', 'baz']) as o:
            output = o

        expected_output = """Running shell command: foo bar baz

foobar

bazfoo
"""

        self.assertEqual(output, expected_output)
