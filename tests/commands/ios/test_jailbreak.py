import unittest
from unittest import mock

from objection.commands.ios.jailbreak import disable, simulate


class TestJailbreak(unittest.TestCase):
    @mock.patch('objection.commands.ios.jailbreak.FridaRunner')
    def test_disable(self, mock_runner):
        disable([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    @mock.patch('objection.commands.ios.jailbreak.FridaRunner')
    def test_simulate(self, mock_runner):
        simulate([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
