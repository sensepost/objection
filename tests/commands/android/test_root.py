import unittest
from unittest import mock

from objection.commands.android.root import disable, simulate


class TestRoot(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_disable(self, mock_api):
        disable([])

        self.assertTrue(mock_api.return_value.android_root_detection_disable.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_simulate(self, mock_api):
        simulate([])

        self.assertTrue(mock_api.return_value.android_root_detection_enable.called)
