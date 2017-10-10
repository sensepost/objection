import unittest
from unittest import mock

from objection.utils.patchers.base import BasePlatformGadget, BasePlatformPatcher
from ...helpers import capture


class TestBasePlatformGadget(unittest.TestCase):
    @mock.patch('objection.utils.patchers.base.Github')
    def setUp(self, mock_github):
        self.gadget = BasePlatformGadget(github=mock_github)

    @mock.patch('objection.utils.patchers.base.os')
    def test_sets_version_to_zero_if_no_local_record_is_found(self, mock_os):
        mock_os.path.exists.return_value = False
        version = self.gadget.get_local_version('test')

        self.assertEqual(version, '0')


class TestBasePlatformPatcher(unittest.TestCase):
    def setUp(self):
        pass

    @mock.patch('objection.utils.patchers.base.BasePlatformPatcher._check_commands', mock.Mock(return_value=True))
    def test_inits_base_patcher(self):
        base_patcher = BasePlatformPatcher()

        self.assertTrue(base_patcher.have_all_commands)
        self.assertEqual(base_patcher.command_run_timeout, 300)

    @mock.patch('objection.utils.patchers.base.BasePlatformPatcher._check_commands', mock.Mock(return_value=True))
    def test_are_requirements_met_returns_true_if_met(self):
        base_patcher = BasePlatformPatcher()

        self.assertTrue(base_patcher.are_requirements_met())

    @mock.patch('objection.utils.patchers.base.BasePlatformPatcher._check_commands', mock.Mock(return_value=False))
    def test_are_requirements_met_returns_false_if_not_met(self):
        base_patcher = BasePlatformPatcher()

        self.assertFalse(base_patcher.are_requirements_met())

    @mock.patch('objection.utils.patchers.base.BasePlatformPatcher.__init__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.base.shutil')
    def test_check_commands_finds_commands_and_sets_location(self, mock_shutil):
        mock_shutil.which.return_value = '/bin/test'

        base_patcher = BasePlatformPatcher()
        base_patcher.required_commands = {
            'aapt': {
                'installation': 'apt install aapt (Kali Linux)'
            }
        }

        check_result = base_patcher._check_commands()

        self.assertTrue(check_result)
        self.assertEqual(base_patcher.required_commands['aapt']['location'], '/bin/test')

    @mock.patch('objection.utils.patchers.base.BasePlatformPatcher.__init__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.base.shutil')
    def test_check_commands_fails_to_find_command_and_displays_error(self, mock_shutil):
        mock_shutil.which.return_value = None

        base_patcher = BasePlatformPatcher()
        base_patcher.required_commands = {
            'aapt': {
                'installation': 'apt install aapt (Kali Linux)'
            }
        }

        with capture(base_patcher._check_commands) as o:
            output = o

        self.assertEqual(output, 'Unable to find aapt. Install it with:'
                                 ' apt install aapt (Kali Linux) before continuing.\n')
