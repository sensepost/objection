import unittest
from unittest import mock

from objection.commands.ios.nsuserdefaults import get, set
from ...helpers import capture


class TestNsuserdefaults(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_get(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_get.return_value = 'foo'

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'foo\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_string(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_set.return_value = True

        with capture(set, ['testKey', 'testValue']) as o:
            output = o

        self.assertIn('Successfully set testKey', output)
        mock_api.return_value.ios_nsuser_defaults_set.assert_called_once_with('testKey', 'testValue', 'string')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_bool(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_set.return_value = True

        with capture(set, ['isEnabled', 'true']) as o:
            output = o

        self.assertIn('Successfully set isEnabled', output)
        mock_api.return_value.ios_nsuser_defaults_set.assert_called_once_with('isEnabled', True, 'bool')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_int(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_set.return_value = True

        with capture(set, ['count', '42']) as o:
            output = o

        self.assertIn('Successfully set count', output)
        mock_api.return_value.ios_nsuser_defaults_set.assert_called_once_with('count', 42, 'int')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_with_explicit_type(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_set.return_value = True

        with capture(set, ['version', '2.5', '--type', 'float']) as o:
            output = o

        self.assertIn('Successfully set version', output)
        mock_api.return_value.ios_nsuser_defaults_set.assert_called_once_with('version', 2.5, 'float')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_missing_arguments(self, mock_api):
        with capture(set, ['onlyKey']) as o:
            output = o

        self.assertIn('Usage:', output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_no_arguments(self, mock_api):
        with capture(set, []) as o:
            output = o

        self.assertIn('Usage:', output)
