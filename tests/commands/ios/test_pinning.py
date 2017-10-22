import unittest
from unittest import mock

from objection.commands.ios.pinning import ios_disable, _should_ignore_ios10_tls_helper_hook, _should_be_quiet


class TestPinning(unittest.TestCase):
    @mock.patch('objection.commands.ios.pinning.FridaRunner')
    def test_disable(self, mock_runner):
        ios_disable([])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    def test_should_ignore_ios_10_helper_returns_true(self):
        result = _should_ignore_ios10_tls_helper_hook(['test', '--ignore-ios10-tls-helper'])
        self.assertTrue(result)

    def test_should_ignore_ios_10_helper_returns_false(self):
        result = _should_ignore_ios10_tls_helper_hook(['test'])
        self.assertFalse(result)

    def test_should_be_quiet_returns_true(self):
        result = _should_be_quiet(['test', '--quiet'])
        self.assertTrue(result)

    def test_should_be_quiet_returns_false(self):
        result = _should_be_quiet(['test'])
        self.assertFalse(result)
