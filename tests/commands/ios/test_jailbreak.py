import unittest
from unittest import mock

from objection.commands.ios.jailbreak import disable, simulate


class TestJailbreak(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_disable(self, mock_api):
        disable([])

        self.assertTrue(mock_api.return_value.ios_jailbreak_disable.called)

    @mock.patch('objection.commands.ios.jailbreak.FridaRunner')
    def test_simulate(self, mock_runner):
        simulate([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
