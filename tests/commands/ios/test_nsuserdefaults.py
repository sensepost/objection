import unittest
from unittest import mock

from objection.commands.ios.nsuserdefaults import get
from ...helpers import capture


class TestNsuserdefaults(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_get(self, mock_api):
        mock_api.return_value.ios_nsuser_defaults_get.return_value = 'foo'

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'foo\n')
