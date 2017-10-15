import unittest
from unittest import mock

from objection.__init__ import __version__
from objection.utils.update_checker import check_version
from ..helpers import capture


class TestUpdateChecker(unittest.TestCase):
    @mock.patch('objection.utils.update_checker.random')
    def test_check_if_update_is_skipped_if_false_random(self, mock_random):
        mock_random.choice.return_value = False

        with capture(check_version) as o:
            output = o

        self.assertEqual(output, '')

    @mock.patch('objection.utils.update_checker.random')
    @mock.patch('objection.utils.update_checker.requests')
    def test_checks_for_update_and_alerts(self, mock_requests, mock_random):
        mock_random.choice.return_value = True

        mock_http_response = mock.Mock()
        mock_http_response.json.return_value = {
            'tag_name': '999.0'
        }

        mock_requests.get.return_value = mock_http_response

        with capture(check_version) as o:
            output = o

        expected_output = """

A newer version of objection is available!
You have v{0} and v999.0 is ready for download.

Upgrade with: pip3 install objection --upgrade
For more information, please see: https://github.com/sensepost/objection/wiki/Updating

""".format(__version__)

        self.assertEqual(output, expected_output)

    @mock.patch('objection.utils.update_checker.random')
    @mock.patch('objection.utils.update_checker.requests')
    def test_checks_for_update_and_fails_with_exception(self, mock_requests, mock_random):
        mock_random.choice.return_value = True

        mock_http_response = mock.Mock()
        mock_http_response.json.side_effect = Exception()

        mock_requests.get.return_value = mock_http_response

        with capture(check_version) as o:
            output = o

        self.assertEqual(output, '')
        self.assertTrue(mock_requests.get.called)
