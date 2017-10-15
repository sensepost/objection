import unittest
from unittest import mock

from objection.commands.ios.pinning import ios_disable


class TestPinning(unittest.TestCase):
    @mock.patch('objection.commands.ios.pinning.FridaRunner')
    def test_disable(self, mock_runner):
        ios_disable([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
