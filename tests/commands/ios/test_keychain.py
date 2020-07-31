import unittest
from unittest import mock

from objection.commands.ios.keychain import _should_output_json, dump, dump_raw, clear, add, \
    _data_flag_has_identifier, _get_flag_value, _should_do_smart_decode
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

    def test_data_flag_check_ignored_without_data_flag(self):
        result = _data_flag_has_identifier(['--key', 'test_key'])

        self.assertTrue(result)

    def test_data_flag_is_checked_when_flag_is_specified(self):
        result = _data_flag_has_identifier(['--key', 'test_key', '--data', 'foo'])

        self.assertFalse(result)

    def test_data_flag_is_checked_when_only_data_flag_is_specified_without_key(self):
        result = _data_flag_has_identifier(['--data', 'foo'])

        self.assertFalse(result)

    def test_should_do_smart_decode_returns_true(self):
        result = _should_do_smart_decode(['--json', '--smart'])

        self.assertTrue(result)

    def test_should_do_smart_decode_returns_false(self):
        result = _should_do_smart_decode(['--json'])

        self.assertFalse(result)

    def test_get_flag_value_gets_value_of_flag(self):
        result = _get_flag_value(['--key', 'test_value'], '--key')

        self.assertEqual(result, 'test_value')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump_to_screen_handles_empty_data(self, mock_api):
        mock_api.return_value.keychain_list.return_value = []

        with capture(dump, []) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created    Accessible    ACL    Type    Account    Service    Data
---------  ------------  -----  ------  ---------  ---------  ------
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump_to_screen(self, mock_api):
        mock_api.return_value.ios_keychain_list.return_value = [
            {'account': 'foo', 'create_date': 'now', 'accessible_attribute': 'None',
             'access_control': 'None', 'item_class': 'kSecClassGeneric', 'service': 'foo',
             'data': 'bar'}
        ]

        with capture(dump, []) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created    Accessible    ACL    Type    Account    Service    Data
---------  ------------  -----  ------  ---------  ---------  ------
now        None          None           foo        foo        bar
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_dump_raw(self, mock_api):
        mock_api.return_value.ios_keychain_list_raw.return_value = []

        with capture(dump_raw, []) as o:
            _ = o

        self.assertTrue(mock_api.return_value.ios_keychain_list_raw.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.ios.keychain.open', create=True)
    def test_dump_to_json(self, mock_open, mock_api):
        mock_api.return_value.ios_keychain_list.return_value = [
            {'access_control': '', 'account': '', 'alias': '', 'comment': '',
             'create_date': '2018-07-21 18:11:15 +0000', 'creator': '',
             'custom_icon': '', 'data': 'bar', 'description': '',
             'entitlement_group': '8AH3PS2AS7.za.sensepost.ipewpew',
             'generic': '', 'invisible': '', 'item_class': 'genp',
             'label': '', 'modification_date': '2018-07-21 18:11:15 +0000',
             'negative': '', 'protected': '', 'script_code': '',
             'service': 'foos', 'type': ''}]

        with capture(dump, ['--json', 'foo.json']) as o:
            output = o

        expected_output = """Note: You may be asked to authenticate using the devices passcode or TouchID
Dumping the iOS keychain...
Writing keychain as json to foo.json...
Dumped keychain to: foo.json
"""
        self.assertEqual(output, expected_output)
        self.assertTrue(mock_open.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    @mock.patch('objection.commands.ios.keychain.click.confirm')
    def test_clear(self, mock_confirm, mock_api):
        mock_confirm.return_value = True

        with capture(clear, []) as o:
            output = o

        self.assertEqual(output, 'Clearing the keychain...\nKeychain cleared\n')
        self.assertTrue(mock_api.return_value.ios_keychain_empty.called)

    def test_adds_item_validates_data_key_to_need_identifier(self):
        with capture(add, ['--data', 'test_data']) as o:
            output = o

        self.assertEqual(output, 'When specifying the --data flag, either --account or --server should also be added\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_adds_item_successfully(self, mock_api):
        mock_api.return_value.keychain_add.return_value = True

        with capture(add, ['--account', 'test_key', '--data', 'test_data']) as o:
            output = o

        self.assertEqual(output, """Adding a new entry to the iOS keychain...
Account:  test_key
Service:  None
Data:     test_data
Successfully added the keychain item\n""")

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_adds_item_with_failure(self, mock_api):
        mock_api.return_value.ios_keychain_add.return_value = False

        with capture(add, ['--service', 'test_key', '--data', 'test_data']) as o:
            output = o

        self.assertEqual(output, """Adding a new entry to the iOS keychain...
Account:  None
Service:  test_key
Data:     test_data
Failed to add the keychain item\n""")
