import unittest
from unittest import mock

from objection.state.sqlite import sqlite_manager_state
from ..helpers import capture


class TestSQLite(unittest.TestCase):
    def tearDown(self):
        sqlite_manager_state.file = sqlite_manager_state.temp_file = None

    def test_reports_not_connected_by_default(self):
        status = sqlite_manager_state.is_connected()

        self.assertFalse(status)

    def test_reports_connected_with_file_and_tempfile_set(self):
        sqlite_manager_state.file = 'foo'
        sqlite_manager_state.temp_file = 'bar'

        status = sqlite_manager_state.is_connected()

        self.assertTrue(status)

    @mock.patch('objection.state.sqlite.tempfile')
    def test_gets_new_cache_directory_for_temp_storage(self, mock_tempfile):
        mock_tempfile.mkstemp.return_value = 1, '/tmp/foo'

        directory = sqlite_manager_state.get_cache_dir()

        self.assertEqual(directory, '/tmp/foo')

    def test_gets_existing_temp_directory_for_temp_storage(self):
        sqlite_manager_state.temp_file = '/foo/bar'

        directory = sqlite_manager_state.get_cache_dir()

        self.assertEqual(directory, '/foo/bar')

    @mock.patch('objection.state.sqlite.os')
    def test_will_cleanup_when_connected(self, mock_os):
        mock_os.remove.return_value = None

        sqlite_manager_state.file = 'foo'
        sqlite_manager_state.temp_file = 'bar'

        with capture(sqlite_manager_state.cleanup) as o:
            output = o

        self.assertEqual(output, '[sqlite manager] Removing cached copy of SQLite database: foo at bar\n')
        self.assertIsNone(sqlite_manager_state.file)
        self.assertIsNone(sqlite_manager_state.temp_file)
        self.assertIsNone(sqlite_manager_state.full_remote_file)

    def test_representation(self):
        self.assertEqual(repr(sqlite_manager_state), '<File:None LocalTemp:None>')
