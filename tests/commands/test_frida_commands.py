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

    @mock.patch('objection.commands.frida_commands.FridaRunner')
    def test_gets_frida_environment(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).frida_version = '10.0.1'
        type(mock_response).process_arch = 'arm'
        type(mock_response).process_platform = 'unknown'
        type(mock_response).process_has_debugger = True

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(frida_environment, []) as o:
            output = o

        expected_output = """--------------------  -------
Frida Version         10.0.1
Process Architecture  arm
Process Platform      unknown
Debugger Attached     True
--------------------  -------
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.frida_commands.FridaRunner')
    def test_gets_frida_environment_and_handles_failed_hook(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(frida_environment, []) as o:
            output = o

        self.assertEqual(output, 'Failed to get frida environment with error: test\n')

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
