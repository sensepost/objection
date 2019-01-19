import unittest
from unittest import mock

from objection.commands.android.pinning import android_disable


class TestPinning(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_pinning_disable(self, mock_api):
        android_disable([])

        self.assertTrue(mock_api.return_value.android_ssl_pinning_disable.called)
