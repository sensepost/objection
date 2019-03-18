import unittest
from unittest import mock

from objection.commands.ios.plist import cat
from objection.state.device import device_state, Ios
from ...helpers import capture


class TestPlist(unittest.TestCase):
    def test_cat_validates_arguments(self):
        with capture(cat, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios plist cat <remote_plist>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_cat_with_full_path(self, mock_api):
        mock_api.return_value.ios_plist_read.return_value = 'foo'

        with capture(cat, ['/foo']) as o:
            output = o

        self.assertEqual(output, 'foo\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.ios.plist.filemanager')
    def test_cat_with_relative(self, mock_file_manager, mock_api):
        mock_file_manager.pwd.return_value = '/baz'
        mock_api.return_value.ios_plist_read.return_value = 'foobar'

        device_state.device_type = Ios

        with capture(cat, ['foo']) as o:
            output = o

        self.assertEqual(output, 'foobar\n')
