import unittest
from unittest import mock

from objection.commands.ios.plist import cat
from ...helpers import capture


class TestPlist(unittest.TestCase):
    def test_cat_validates_arguments(self):
        with capture(cat, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios plist cat <remote_plist>\n')

    @mock.patch('objection.commands.ios.plist.FridaRunner')
    def test_cat_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(cat, ['/foo']) as o:
            output = o

        self.assertEqual(output, 'Failed to get plist with error: test\n')

    @mock.patch('objection.commands.ios.plist.FridaRunner')
    def test_cat_with_full_path(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = 'foo'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(cat, ['/foo']) as o:
            output = o

        self.assertEqual(output, 'foo\n')

    @mock.patch('objection.commands.ios.plist.FridaRunner')
    @mock.patch('objection.commands.ios.plist.filemanager')
    def test_cat_with_relative(self, mock_file_manager, mock_runner):
        mock_file_manager.pwd.return_value = '/baz'

        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = 'foobar'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(cat, ['foo']) as o:
            output = o

        self.assertEqual(output, 'foobar\n')
