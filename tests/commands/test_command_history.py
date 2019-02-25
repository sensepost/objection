import unittest
from unittest import mock

from objection.commands.command_history import history, save, clear
from objection.state.app import app_state
from ..helpers import capture


class TestCommandHistory(unittest.TestCase):
    def setUp(self):
        app_state.successful_commands = ['foo', 'bar']

    def tearDown(self):
        app_state.successful_commands = []

    def test_prints_command_history(self):
        with capture(history, []) as o:
            output = o

        expected_output = """Unique commands run in current session:
foo
bar
"""

        self.assertEqual(output, expected_output)

    def test_save_validates_arguments(self):
        with capture(save, []) as o:
            output = o

        self.assertEqual(output, 'Usage: commands save <local destination>\n')

    @mock.patch('objection.commands.command_history.open', create=True)
    def test_save_saves_to_file(self, mock_open):
        with capture(save, ['foo.rc']) as o:
            output = o

        self.assertEqual(output, 'Saved commands to: foo.rc\n')
        self.assertTrue(mock_open.called)

    def test_clear_clears_command_history(self):
        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Command history cleared.\n')
        self.assertEqual(len(app_state.successful_commands), 0)
