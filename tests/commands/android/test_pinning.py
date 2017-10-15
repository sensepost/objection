import unittest
from unittest import mock

from objection.commands.android.pinning import android_disable


class TestPinning(unittest.TestCase):
    @mock.patch('objection.commands.android.pinning.FridaRunner')
    def test_pinning_disable(self, mock_runner):
        android_disable([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)
