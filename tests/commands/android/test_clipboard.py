import unittest
from unittest import mock

from objection.commands.android.clipboard import monitor


class TestClipboard(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_monitor(self, mock_api):
        monitor([])

        self.assertTrue(mock_api.return_value.android_monitor_clipboard.called)
