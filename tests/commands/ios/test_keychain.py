import unittest
from unittest import mock

from objection.commands.ios.keychain import _should_output_json, dump, clear, add, \
    _has_minimum_flags_to_add_item, _get_flag_value
from ...helpers import capture


class TestKeychain(unittest.TestCase):
    def test_should_output_json_in_arguments_returns_true(self):
        result = _should_output_json([
            '--test',
            '--json'
        ])

        self.assertTrue(result)

    def test_should_output_json_in_arguments_returns_false(self):
        result = _should_output_json([
            '--test',
        ])

        self.assertFalse(result)

    def test_dump_validates_arguments_if_json_output_is_wanted(self):
        with capture(dump, ['--json']) as o:
            output = o

        self.assertEqual(output, 'Usage: ios keychain dump (--json <local destination>)\n')

    def test_has_minimum_flags_to_add_item_returns_true(self):
        result = _has_minimum_flags_to_add_item(['--key', 'test_key', '--data', 'test_data'])

        self.assertTrue(result)

    def test_has_minumum_flags_to_add_item_returns_false(self):
        result = _has_minimum_flags_to_add_item(['--key', 'test_key'])

        self.assertFalse(result)

    def test_get_flag_value_gets_value_of_flag(self):
        result = _get_flag_value(['--key', 'test_value'], '--key')

        self.assertEqual(result, 'test_value')

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_dump_to_screen_handles_hook_errors(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_message = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump, []) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Get all of the attributes by adding `--json keychain.json` to this command
Reading the iOS keychain...
Failed to get keychain items with error: test
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_dump_to_screen_handles_empty_data(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = None

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump, []) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Get all of the attributes by adding `--json keychain.json` to this command
Reading the iOS keychain...
No keychain data could be found
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_dump_to_screen(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = [{
            'item_class': 'a',
            'account': 'b',
            'service': 'c',
            'generic': 'd',
            'data': 'e'
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump, []) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Get all of the attributes by adding `--json keychain.json` to this command
Reading the iOS keychain...

Class    Account    Service    Generic    Data
-------  ---------  ---------  ---------  ------
a        b          c          d          e
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    @mock.patch('objection.commands.ios.keychain.open', create=True)
    def test_dump_to_json(self, mock_open, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = [{
            'item_class': 'a',
            'account': 'b',
            'service': 'c',
            'generic': 'd',
            'data': 'e'
        }]

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(dump, ['--json', 'foo.json']) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Reading the iOS keychain...
Writing full keychain as json to foo.json...
Dumped full keychain to: foo.json
"""
        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_clear_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_message = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Clearing the keychain...\nFailed to clear keychain items with error: test\n')

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_clear(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Clearing the keychain...\nKeychain cleared\n')

    def test_adds_item_validates_arguments(self):
        with capture(add, ['--key', 'test_key']) as o:
            output = o

        self.assertEqual(output, 'Usage: ios keychain add --key <key name> --data <entry data>\n')

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_adds_item_successfully(self, mock_runner):
        mock_api = mock.Mock()
        mock_api.add.return_value = True

        mock_runner.return_value.rpc_exports.return_value = mock_api

        with capture(add, ['--key', 'test_key', '--data', 'test_data']) as o:
            output = o

        self.assertEqual(output, 'Adding a new entry to the iOS keychain...\nKey:       test_key\n'
                                 'Value:     test_data\nSuccessfully added the keychain item\n')

    @mock.patch('objection.commands.ios.keychain.FridaRunner')
    def test_adds_item_with_failure(self, mock_runner):
        mock_api = mock.Mock()
        mock_api.add.return_value = False

        mock_runner.return_value.rpc_exports.return_value = mock_api

        with capture(add, ['--key', 'test_key', '--data', 'test_data']) as o:
            output = o

        self.assertEqual(output, 'Adding a new entry to the iOS keychain...\nKey:       test_key\n'
                                 'Value:     test_data\nFailed to add the keychain item\n')
