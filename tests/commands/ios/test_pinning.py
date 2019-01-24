import unittest
from unittest import mock

from objection.commands.ios.pinning import ios_disable, _should_be_quiet


class TestPinning(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_disable(self, mock_api):
        ios_disable([])

        self.assertTrue(mock_api.return_value.ios_pinning_disable.called)

    def test_should_be_quiet_returns_true(self):
        result = _should_be_quiet(['test', '--quiet'])
        self.assertTrue(result)

    def test_should_be_quiet_returns_false(self):
        result = _should_be_quiet(['test'])
        self.assertFalse(result)
