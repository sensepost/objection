import unittest
from unittest import mock

from objection.commands.mobile_packages import patch_ios_ipa, patch_android_apk
from ..helpers import capture


class TestMobilePackages(unittest.TestCase):
    @mock.patch('objection.commands.mobile_packages.Github')
    @mock.patch('objection.commands.mobile_packages.IosGadget')
    @mock.patch('objection.commands.mobile_packages.IosPatcher')
    @mock.patch('objection.commands.mobile_packages.shutil')
    @mock.patch('objection.commands.mobile_packages.os')
    def test_patching_ios_ipa(self, mock_os, mock_shutil, mock_iospatcher, mock_iosgadget, mock_github):
        mock_github.return_value.get_latest_version.return_value = '1.0'
        mock_iosgadget.return_value.get_local_version.return_value = '0.9'

        mock_iospatcher.return_value.are_requirements_met.return_value = True
        mock_iospatcher.return_value.get_patched_ipa_path.return_value = '/foo/ipa'

        with capture(patch_ios_ipa, 'test.ipa', '00-11', '/foo', '', False, False) as o:
            output = o

        expected_output = """Using latest Github gadget version: 1.0
Remote FridaGadget version is v1.0, local is v0.9. Downloading...
Patcher will be using Gadget version: 1.0
Copying final ipa from /foo/ipa to current directory...
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_shutil.copyfile.called)
        self.assertTrue(mock_os.path.join.called)
        self.assertTrue(mock_os.path.abspath.called)
        self.assertTrue(mock_os.path.basename.called)

    @mock.patch('objection.commands.mobile_packages.Github')
    @mock.patch('objection.commands.mobile_packages.AndroidGadget')
    @mock.patch('objection.commands.mobile_packages.AndroidPatcher')
    @mock.patch('objection.commands.mobile_packages.shutil')
    @mock.patch('objection.commands.mobile_packages.os')
    @mock.patch('objection.commands.mobile_packages.delegator')
    @mock.patch('objection.commands.mobile_packages.input', create=True)
    def test_patching_android_apk(self, mock_input, mock_delegator, mock_os, mock_shutil, mock_androidpatcher,
                                  mock_androidgadget, mock_github):
        mock_github.return_value.get_latest_version.return_value = '1.0'
        mock_androidgadget.return_value.get_local_version.return_value = '0.9'

        mock_androidpatcher.return_value.are_requirements_met.return_value = True
        mock_androidpatcher.return_value.get_temp_working_directory.return_value = '/foo/apk'
        mock_androidpatcher.return_value.get_patched_apk_path.return_value = '/foo/bar/apk'

        mock_delegator_output = mock.Mock()
        type(mock_delegator_output).out = 'x86'

        mock_delegator.run.return_value = mock_delegator_output
        mock_input.return_value = ''

        with capture(patch_android_apk, 'test.apk', '', True, False) as o:
            output = o

        expected_output = """No architecture specified. Determining it using `adb`...
Detected target device architecture as: x86
Using latest Github gadget version: 1.0
Remote FridaGadget version is v1.0, local is v0.9. Downloading...
Patcher will be using Gadget version: 1.0
Patching paused. The next step is to rebuild the APK. If you require any manual fixes, the current temp directory is:
/foo/apk
Copying final apk from /foo/bar/apk to test.objection.apk in current directory...
"""

        self.assertEqual(output, expected_output)
        self.assertTrue(mock_shutil.copyfile.called)
        self.assertTrue(mock_os.path.join.called)
        self.assertTrue(mock_os.path.abspath.called)
