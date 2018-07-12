import unittest
from unittest import mock

from objection.commands.ios.nsurlcredentialstorage import dump
from ...helpers import capture


class TestNsusercredentialstorage(unittest.TestCase):
    @mock.patch('objection.commands.ios.nsurlcredentialstorage.FridaRunner')
    def test_dump(self, mock_runner):
        mock_runner.return_value.rpc_exports.return_value.dump.return_value = [{"Foo": "Bar"}]

        with capture(dump, []) as o:
            output = o

        expected_output = """\nFoo
-----
Bar

Found 1 credentials\n"""

        self.assertEqual(output, expected_output)
