import unittest
from unittest import mock

from objection.commands.ios.cookies import get
from ...helpers import capture


class TestCookies(unittest.TestCase):
    @mock.patch('objection.commands.ios.cookies.FridaRunner')
    def test_get_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'Failed to get cookies with error: test\n')

    @mock.patch('objection.commands.ios.cookies.FridaRunner')
    def test_get_handles_empty_data(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = None

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(get, []) as o:
            output = o

        self.assertEqual(output, 'No cookies found\n')

    @mock.patch('objection.commands.ios.cookies.FridaRunner')
    def test_get(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = [{
            'name': 'foo',
            'value': 'bar',
            'expiresDate': '01-01-1970 00:00:00 +0000',
            'domain': 'foo.com',
            'path': '/',
            'isSecure': 'false',
            'isHTTPOnly': 'true'
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(get, []) as o:
            output = o

        expected_output = """Name    Value    Expires                    Domain    Path    Secure    HTTPOnly
------  -------  -------------------------  --------  ------  --------  ----------
foo     bar      01-01-1970 00:00:00 +0000  foo.com   /       false     true
"""

        self.assertEqual(output, expected_output)
