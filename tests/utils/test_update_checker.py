import unittest
from unittest import mock

from objection.utils.update_checker import check_version
from ..helpers import capture


class TestUpdateChecker(unittest.TestCase):
    @mock.patch('objection.utils.update_checker.random')
    def test_check_if_update_is_skipped_if_false_random(self, mock_random):
        mock_random.choice.return_value = False

        with capture(check_version) as o:
            output = o

        self.assertEqual(output, '')
