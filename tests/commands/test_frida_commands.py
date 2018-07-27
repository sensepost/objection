import unittest
from unittest import mock

from objection.commands.frida_commands import _should_disable_exception_handler, frida_environment, load_script
from ..helpers import capture


class TestFridaCommands(unittest.TestCase):
    def test_detects_no_exception_handler_argument(self):
        result = _should_disable_exception_handler([
            '--test',
            '--no-exception-handler'
        ])

        self.assertTrue(result)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_gets_frida_environment(self, mock_api):
        mock_api.return_value.env_frida.return_value = {'arch': 'x64', 'debugger': True, 'heap': 6988464,
                                                        'platform': 'darwin', 'version': '12.0.3'}

        with capture(frida_environment, []) as o:
            output = o

        expected_output = """--------------------  -------
Frida Version         12.0.3
Process Architecture  x64
Process Platform      darwin
Debugger Attached     True
Frida Heap Size       6.7 MiB
--------------------  -------
"""

        self.assertEqual(output, expected_output)

    def test_load_script_validates_arguments(self):
        with capture(load_script, []) as o:
            output = o

        self.assertEqual(output, 'Usage: import <local path to frida-script> '
                                 '(optional name) (optional: --no-exception-handler)\n')

    @mock.patch('objection.commands.frida_commands.os')
    def test_loads_script_fails_with_invalid_file(self, mock_os):
        mock_os.path.isfile.return_value = False

        with capture(load_script, ['foo.js', '--no-exception-handler']) as o:
            output = o

        self.assertEqual(output, 'Unable to import file foo.js\n')

    @mock.patch('objection.commands.frida_commands.FridaRunner')
    @mock.patch('objection.commands.frida_commands.os')
    @mock.patch('objection.commands.frida_commands.open', create=True)
    def test_loads_script_from_home_directory_and_starts_job(self, mock_open, mock_os, mock_runner):
        mock_os.path.isfile.return_value = True
        mock_os.path.expanduser.return_value = '/home/foo'

        load_script(['~/foo.js'])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    @mock.patch('objection.commands.frida_commands.FridaRunner')
    @mock.patch('objection.commands.frida_commands.os')
    @mock.patch('objection.commands.frida_commands.open', create=True)
    def test_loads_script_with_custom_name_and_starts_job(self, mock_open, mock_os, mock_runner):
        mock_os.path.isfile.return_value = True

        load_script(['/foo.js', 'test job'])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
