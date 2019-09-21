import unittest
from unittest import mock

from objection.commands.memory import _is_string_input, dump_all, dump_from_base, list_modules, list_exports, \
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

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_dump_all(self, mock_open, mock_api):
        mock_api.return_value.memory_list_ranges.return_value = [
            {'size': 100, 'base': '0x7fff90800000'}
        ]
        mock_api.return_value.memory_dump.return_value = b'\x00'

        with capture(dump_all, ['/foo']) as o:
            output = o

        expected_output = """Will dump 1 rw- images, totalling 100.0 B
Memory dumped to file: /foo
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    def test_dump_from_base_validates_arguments(self):
        with capture(dump_from_base, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory dump from_base '
                                 '<base_address> <size_to_dump> <local_destination>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_dump_from_base(self, mock_open, mock_api):
        mock_api.return_value.memory_dump.return_value = b'\x00'

        with capture(dump_from_base, ['0x00008000', '200', '/foo']) as o:
            output = o

        expected_output = """Dumping 200.0 B from 0x00008000 to /foo
Memory dumped to file: /foo
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_list_modules_without_errors_without_json_flag(self, mock_api):
        mock_api.return_value.memory_list_modules.return_value = [{
            'name': 'test',
            'base': 0x00008000,
            'size': 200,
            'path': '/foo'
        }]

        with capture(list_modules, []) as o:
            output = o

        expected_outut = """Save the output by adding `--json modules.json` to this command
Name      Base  Size           Path
------  ------  -------------  ------
test     32768  200 (200.0 B)  /foo
"""

        self.assertEqual(output, expected_outut)

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_list_modules_without_errors_with_json_flag(self, mock_open, mock_api):
        mock_api.return_value.memory_list_modules.return_value = [{
            'name': 'test',
            'base': 0x00008000,
            'size': 200,
            'path': '/foo'
        }]

        with capture(list_modules, ['--json', 'foo']) as o:
            output = o

        expected_outut = """Writing modules as json to foo...
Wrote modules to: foo
"""

        self.assertEqual(output, expected_outut)
        self.assertTrue(mock_open.called)

    def test_dump_exports_validates_arguments_without_json_flag(self):
        with capture(list_exports, []) as o:
            output = o

        expected = """Save the output by adding `--json exports.json` to this command
Usage: memory list exports <module name>
"""

        self.assertEqual(output, expected)

    def test_dump_exports_validates_arguments_with_json_flag(self):
        with capture(list_exports, ['--json']) as o:
            output = o

        self.assertEqual(output, 'Usage: memory list exports <module name> (--json <local destination>)\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump_exports_without_error(self, mock_api):
        mock_api.return_value.memory_list_exports.return_value = [{
            'name': 'test',
            'address': 0x00008000,
            'type': 'function'
        }]

        with capture(list_exports, ['foo']) as o:
            output = o

        expected_outut = """Save the output by adding `--json exports.json` to this command
Type      Name      Address
--------  ------  ---------
function  test        32768
"""

        self.assertEqual(output, expected_outut)

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.memory.open', create=True)
    def test_dump_exports_without_error_as_json(self, mock_open, mock_api):
        mock_api.return_value.memory_list_exports.return_value = [{
            'name': 'test',
            'address': 0x00008000,
            'type': 'function'
        }]

        with capture(list_exports, ['foo', '--json', 'foo']) as o:
            output = o

        expected_outut = """Writing exports as json to foo...
Wrote exports to: foo
"""

        self.assertEqual(output, expected_outut)
        self.assertTrue(mock_open.called)

    def test_find_pattern_validates_arguments(self):
        with capture(find_pattern, []) as o:
            output = o

        self.assertEqual(output, 'Usage: memory search "<pattern eg: 41 41 41 ?? 41>" (--string) (--offsets-only)\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_find_pattern_without_string_argument(self, mock_api):
        mock_api.return_value.memory_search.return_value = ['0x08000000']

        with capture(find_pattern, ['41 41 41']) as o:
            output = o

        expected_output = """Searching for: 41 41 41
Pattern matched at 1 addresses
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_find_pattern_with_string_argument(self, mock_api):
        mock_api.return_value.memory_search.return_value = ['0x08000000']

        with capture(find_pattern, ['foo-bar-baz', '--string']) as o:
            output = o

        expected_output = """Searching for: 66 6f 6f 2d 62 61 72 2d 62 61 7a
Pattern matched at 1 addresses
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_find_pattern_without_string_argument_with_offets_only(self, mock_api):
        mock_api.return_value.memory_search.return_value = ['0x08000000']

        with capture(find_pattern, ['41 41 41', '--offsets-only']) as o:
            output = o

        expected_output = """Searching for: 41 41 41
Pattern matched at 1 addresses
0x08000000
"""

        self.assertEqual(output, expected_output)
