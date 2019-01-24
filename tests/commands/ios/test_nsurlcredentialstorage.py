import unittest
from unittest import mock

from objection.commands.ios.nsurlcredentialstorage import dump
from ...helpers import capture


class TestNsusercredentialstorage(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump(self, mock_api):
        mock_api.return_value.ios_credential_storage.return_value = [{
            'protocol': 'https',
            'host': 'foo.bar',
            'port': '80',
            'authMethod': 'NSURLAuthenticationMethodDefault',
            'user': 'foo',
            'password': 'bar',
        }]

        with capture(dump, []) as o:
            output = o

        expected_output = """Protocol    Host       Port  Authentication Method    User    Password
----------  -------  ------  -----------------------  ------  ----------
https       foo.bar      80  Default                  foo     bar
"""

        self.assertEqual(output, expected_output)
