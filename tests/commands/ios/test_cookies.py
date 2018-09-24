import unittest
from unittest import mock

from objection.commands.ios.cookies import get
from ...helpers import capture


class TestCookies(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_get_handles_empty_data(self, mock_api):
        mock_api.return_value.ios_cookies_get.return_value = []

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'No cookies found\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_get(self, mock_api):
        mock_api.return_value.ios_cookies_get.return_value = [{
            'name': 'foo',
            'value': 'bar',
            'expiresDate': '01-01-1970 00:00:00 +0000',
            'domain': 'foo.com',
            'path': '/',
            'isSecure': 'false',
            'isHTTPOnly': 'true'
        }]

        with capture(get, []) as o:
            output = o

        expected_output = """Name    Value    Expires                    Domain    Path    Secure    HTTPOnly
------  -------  -------------------------  --------  ------  --------  ----------
foo     bar      01-01-1970 00:00:00 +0000  foo.com   /       false     true
"""

        self.assertEqual(output, expected_output)
