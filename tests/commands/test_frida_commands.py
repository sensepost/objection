import unittest
from unittest import mock

from objection.commands.frida_commands import _should_disable_exception_handler, frida_environment
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
        mock_api.return_value.env_frida.return_value = {
            'arch': 'x64',
            'debugger': True,
            'heap': 6988464,
            'platform': 'darwin',
            'version': '12.0.3',
            'runtime': 'DUK',
            'filename': '/script1.js'
        }

        with capture(frida_environment, []) as o:
            output = o

        expected_output = """--------------------  -----------
Frida Version         12.0.3
Process Architecture  x64
Process Platform      darwin
Debugger Attached     True
Script Runtime        DUK
Script Filename       /script1.js
Frida Heap Size       6.7 MiB
--------------------  -----------
"""

        self.assertEqual(output, expected_output)
