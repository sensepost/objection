import sqlite3
import unittest
from unittest import mock

from objection.commands.sqlite import _get_connection, status, connect, disconnect, schema, execute
from objection.state.sqlite import sqlite_manager_state
from ..helpers import capture


class TestSqlite(unittest.TestCase):
    def tearDown(self):
        sqlite_manager_state.temp_file = None
        sqlite_manager_state.file = None

    def test_connects_sqlite_session(self):
        sqlite_manager_state.temp_file = ':memory:'

        result = _get_connection()

        self.assertIsInstance(result, sqlite3.Connection)

    def test_status_prints_when_not_connected(self):
        with capture(status, []) as o:
            output = o

        self.assertEqual(output, 'Not connected to any database file\n')

    def test_status_prints_when_connected(self):
        sqlite_manager_state.temp_file = '/baz/tempdb.sqlite'
        sqlite_manager_state.file = '/foo/bar.sqlite'

        with capture(status, []) as o:
            output = o

        self.assertEqual(output, 'Connected using file: /foo/bar.sqlite (locally cached at: /baz/tempdb.sqlite)\n')

    def test_connect_validates_arguemets(self):
        with capture(connect, []) as o:
            output = o

        self.assertEqual(output, 'Usage: sqlite connect <remote_file>\n')

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    @mock.patch('objection.commands.sqlite.os')
    @mock.patch('objection.commands.sqlite.pwd')
    @mock.patch('objection.commands.sqlite.download')
    @mock.patch('objection.commands.sqlite.open', create=True)
    @mock.patch('objection.commands.sqlite.binascii')
    def test_connect_with_valid_file(self, mock_binascii, mock_open, mock_download, mock_pwd, mock_os,
                                     mock_sqlite_state):
        mock_sqlite_state.is_connected.return_value = False
        mock_pwd.return_value = '/baz'
        mock_binascii.hexlify.return_value = b'53514c69746520666f726d6174203300'

        with capture(connect, ['/foo/bar.sqlite']) as o:
            output = o

        expected_output = """Caching local copy of database file...
Validating SQLite database format
Connected to SQLite database at: /foo/bar.sqlite
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_download.called)
        self.assertTrue(mock_os.path.isabs.called)

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    @mock.patch('objection.commands.sqlite.os')
    @mock.patch('objection.commands.sqlite.pwd')
    @mock.patch('objection.commands.sqlite.download')
    @mock.patch('objection.commands.sqlite.open', create=True)
    @mock.patch('objection.commands.sqlite.binascii')
    def test_connect_with_invalid_file(self, mock_binascii, mock_open, mock_download, mock_pwd, mock_os,
                                       mock_sqlite_state):
        mock_sqlite_state.is_connected.return_value = False
        mock_pwd.return_value = '/baz'
        mock_binascii.hexlify.return_value = b'53514c6974652066'

        with capture(connect, ['/foo/bar.sqlite']) as o:
            output = o

        expected_output = """Caching local copy of database file...
Validating SQLite database format
File does not appear to be a SQLite3 db. Try downloading and manually inspecting this one.
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_download.called)
        self.assertTrue(mock_os.path.isabs.called)

    def test_disconnect_notified_when_not_connected(self):
        with capture(disconnect, []) as o:
            output = o

        self.assertEqual(output, 'Not connected to a database.\n')

    def test_schema_failes_when_not_connected(self):
        with capture(schema, []) as o:
            output = o

        self.assertEqual(output, 'Connect using sqlite connect first!\n')

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    @mock.patch('objection.commands.sqlite.execute')
    def test_schema_executes(self, mock_execute, mock_sqlite_state):
        mock_sqlite_state.is_connected.return_value = True

        schema([])

        self.assertTrue(mock_execute.called)

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    def test_execute_checks_if_connected(self, mock_sqlite_state):
        mock_sqlite_state.is_connected.return_value = False

        with capture(execute, ['select', '*', 'from', 'foo']) as o:
            output = o

        self.assertEqual(output, 'Connect using sqlite connect first!\n')

    def test_execute_validates_arguments(self):
        with capture(execute, ['select']) as o:
            output = o

        self.assertEqual(output, 'Connect using sqlite connect first!\n')

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    @mock.patch('objection.commands.sqlite._get_connection')
    def test_execute_gets_results(self, mock_get_connection, mock_sqlite_state):
        mock_connection = mock.Mock()
        mock_connection.__enter__ = mock.Mock(return_value=None)
        mock_connection.__exit__ = mock.Mock(return_value=None)
        mock_connection.execute.return_value = [
            ['foo', 'bar', 'baz']
        ]

        mock_sqlite_state.is_connected.return_value = True
        mock_get_connection.return_value = mock_connection

        with capture(execute, ['select', '*', 'from', 'foo']) as o:
            output = o

        expected_output = """---  ---  ---
foo  bar  baz
---  ---  ---
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.sqlite.sqlite_manager_state')
    @mock.patch('objection.commands.sqlite._get_connection')
    def test_execute_catches_sqlite_exceptions(self, mock_get_connection, mock_sqlite_state):
        mock_connection = mock.Mock()
        mock_connection.__enter__ = mock.Mock(return_value=None)
        mock_connection.__exit__ = mock.Mock(return_value=None)
        mock_connection.execute.side_effect = sqlite3.OperationalError('foo')

        mock_sqlite_state.is_connected.return_value = True
        mock_get_connection.return_value = mock_connection

        with capture(execute, ['select', '*', 'from', 'foo']) as o:
            output = o

        self.assertEqual(output, 'Error: foo\n')
