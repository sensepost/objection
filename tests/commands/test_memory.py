import unittest
from unittest import mock

from objection.commands.memory import _is_string_input, dump_all, dump_from_base, list_modules, dump_exports, \
    find_pattern
from ..helpers import capture


class MockRange:
    """
        Mock Memory Rage
    """

    def __init__(self):
        self.size = 100
        self.base_address = 0x00008000


class TestMemory(unittest.TestCase):
    def test_parses_is_string_input_flag_from_arguments(self):
        result = _is_string_input([
            '--test',
            '--string'
        ])

        self.assertTrue(result)

    def test_dump_all_validates_arguments(self):
        with capture(dump_all, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory dump all <local destination>\n')

    @mock.patch('objection.commands.memory.FridaRunner')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_dump_all(self, mock_open, mock_runner):
        mock_runner.return_value.rpc_exports.return_value.enumerate_ranges.return_value = [
            {'size': 100, 'base': '0x7fff90800000'}
        ]
        mock_runner.return_value.rpc_exports.return_value.read_bytes.return_value = b'\x00'

        with capture(dump_all, ['/foo']) as o:
            output = o

        expected_output = """Will dump 1 rw- images, totalling 100.0 B
Preparing to dump images
Memory dumped to file: /foo
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    def test_dump_from_base_validates_arguments(self):
        with capture(dump_from_base, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory dump from_base '
                                 '<base_address> <size_to_dump> <local_destination>\n')

    @mock.patch('objection.commands.memory.FridaRunner')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_dump_from_base(self, mock_open, mock_runner):
        mock_runner.return_value.rpc_exports.return_value.read_bytes.return_value = b'\x00'

        with capture(dump_from_base, ['0x00008000', '200', '/foo']) as o:
            output = o

        expected_output = """Dumping 200.0 B from 0x00008000 to /foo
Memory dumped to file: /foo
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_list_modules_without_errors(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).modules = [{
            'name': 'test',
            'base': 0x00008000,
            'size': 200,
            'path': '/foo'
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(list_modules, []) as o:
            output = o

        expected_outut = """Name      Base  Size           Path
------  ------  -------------  ------
test     32768  200 (200.0 B)  /foo
"""

        self.assertEqual(output, expected_outut)

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_list_modules_when_hook_fails(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(list_modules, []) as o:
            output = o

        self.assertEqual(output, 'Failed to list loaded modules in current process with error: test\n')

    def test_dump_exports_validates_arguments(self):
        with capture(dump_exports, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory list exports <module name>\n')

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_dump_exports_without_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).exports = [{
            'name': 'test',
            'address': 0x00008000,
            'type': 'function'
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump_exports, ['foo']) as o:
            output = o

        expected_outut = """Type      Name      Address
--------  ------  ---------
function  test        32768
"""

        self.assertEqual(output, expected_outut)

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_dump_exports_error_when_hook_fails(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump_exports, ['foo']) as o:
            output = o

        self.assertEqual(output, 'Failed to list loaded modules in current process with error: test\n')

    def test_find_pattern_validates_arguments(self):
        with capture(find_pattern, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory search "<pattern eg: 41 41 41 ?? 41>" (--string)\n')

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_find_pattern_without_string_argument(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['0x08000000']

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(find_pattern, ['41 41 41']) as o:
            output = o

        expected_output = """Searching for: 41 41 41
Pattern matched at 1 addresses
0x08000000
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_find_pattern_with_string_argument(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['0x08000000']

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(find_pattern, ['foo-bar-baz', '--string']) as o:
            output = o

        expected_output = """Searching for: 66 6f 6f 2d 62 61 72 2d 62 61 7a
Pattern matched at 1 addresses
0x08000000
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.memory.FridaRunner')
    def test_find_pattern_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(find_pattern, ['foo-bar-baz', '--string']) as o:
            output = o

        expected_output = """Searching for: 66 6f 6f 2d 62 61 72 2d 62 61 7a
Failed to search the current process with error: test
"""

        self.assertEqual(output, expected_output)
