import unittest
from unittest import mock

from objection.commands.android.root import disable, simulate


class TestRoot(unittest.TestCase):
    @mock.patch('objection.commands.android.root.FridaRunner')
    def test_disable(self, mock_runner):
        disable([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    @mock.patch('objection.commands.android.root.FridaRunner')
    def test_simulate(self, mock_runner):
        simulate([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
