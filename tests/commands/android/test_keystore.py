import unittest
from unittest import mock

from objection.commands.android.keystore import entries, clear
from ...helpers import capture


class TestKeystore(unittest.TestCase):
    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_entries_handles_empty_data(self, mock_api):
        mock_api.return_value.android_keystore_list.return_value = []

        with capture(entries, []) as o:
            output = o

        expected_output = """Alias    Key    Certificate
-------  -----  -------------
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_entries_handles(self, mock_api):
        mock_api.return_value.android_keystore_list.return_value = [{
            'alias': 'test',
            'is_key': True,
            'is_certificate': True
        }]

        with capture(entries, []) as o:
            output = o

        expected_output = """Alias    Key    Certificate
-------  -----  -------------
test     True   True
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.android.keystore.click.confirm')
    def test_clear(self, mock_confirm, mock_api):
        mock_confirm.return_value = True

        clear()

        self.assertTrue(mock_api.return_value.android_keystore_clear.called)
