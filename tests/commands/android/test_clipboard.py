import unittest
from unittest import mock

from objection.commands.android.clipboard import monitor


class TestClipboard(unittest.TestCase):
    @mock.patch('objection.commands.android.clipboard.FridaRunner')
    def test_monitor(self, mock_runner):
        monitor([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
