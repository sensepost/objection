import unittest
from unittest import mock

from objection.commands.ios.pasteboard import monitor


class TestPasteboard(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_monitor(self, mock_api):
        monitor([])

        self.assertTrue(mock_api.return_value.ios_monitor_pasteboard.called)
