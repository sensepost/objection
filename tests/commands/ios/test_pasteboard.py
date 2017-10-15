import unittest
from unittest import mock

from objection.commands.ios.pasteboard import monitor


class TestPasteboard(unittest.TestCase):
    @mock.patch('objection.commands.ios.pasteboard.FridaRunner')
    def test_monitor(self, mock_runner):
        monitor([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
