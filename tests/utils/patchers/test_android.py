import os
import unittest
from unittest import mock

from objection.utils.patchers.android import AndroidGadget, AndroidPatcher


class TestAndroidGadget(unittest.TestCase):
    @mock.patch('objection.utils.patchers.android.Github')
    @mock.patch('objection.utils.patchers.android.os')
    def setUp(self, github, mock_os):
        mock_os.path.exists.return_value = True

        self.android_gadget = AndroidGadget(github)

        self.github_get_assets_sample = [
            {
                "url": "https://api.github.com/repos/frida/frida/releases/assets/5005221",
                "id": 5005221,
                "name": "frida-gadget-10.6.8-android-x86.so.xz",
                "label": "",
                "uploader": {
                    "id": 735197,
                },
                "state": "uploaded",
                "size": 12912624,
                "download_count": 1,
                "created_at": "2017-10-07T00:01:10Z",
                "updated_at": "2017-10-07T00:01:17Z",
                "browser_download_url": "https://github.com/frida/frida/releases/download/"
                                        "10.6.8/frida-gadget-10.6.8-android-x86.so.xz"
            }
        ]

    def test_sets_architecture(self):
        self.android_gadget.set_architecture('x86')
        self.assertEqual(self.android_gadget.architecture, 'x86')

    def test_raises_exception_with_invalid_architecture(self):
        with self.assertRaises(Exception) as _:
            self.android_gadget.set_architecture('foo')

    def test_sets_architecture_and_returns_context(self):
        result = self.android_gadget.set_architecture('x86')
        self.assertEqual(type(result), AndroidGadget)

    def test_gets_architecture_when_set(self):
        self.android_gadget.set_architecture('x86')
        architecture = self.android_gadget.get_architecture()

        self.assertEqual(architecture, 'x86')

    def test_gets_frida_library_path(self):
        self.android_gadget.set_architecture('x86')

        frida_path = self.android_gadget.get_frida_library_path()
        self.assertTrue('.objection/android/x86/libfrida-gadget.so' in frida_path)

    def test_fails_to_get_frida_library_path_without_architecture(self):
        with self.assertRaises(Exception) as _:
            self.android_gadget.get_frida_library_path()

    @mock.patch('objection.utils.patchers.android.os')
    def test_checks_if_gadget_exists_if_it_really_exists(self, mock_os):
        mock_os.path.exists.return_value = True
        self.android_gadget.set_architecture('x86')

        status = self.android_gadget.gadget_exists()

        self.assertTrue(status)

    @mock.patch('objection.utils.patchers.android.os')
    def test_checks_if_gadget_exists_if_it_really_does_not_exist(self, mock_os):
        mock_os.path.exists.return_value = False
        self.android_gadget.set_architecture('x86')

        status = self.android_gadget.gadget_exists()

        self.assertFalse(status)

    def test_check_if_gadget_exists_fails_without_architecture(self):
        with self.assertRaises(Exception) as _:
            self.android_gadget.gadget_exists()

    def test_can_find_download_url_for_gadget(self):
        mock_github = mock.MagicMock()
        mock_github.get_assets.return_value = self.github_get_assets_sample

        self.android_gadget.github = mock_github
        self.android_gadget.architecture = 'x86'

        # the method we actually testing here!
        url = self.android_gadget._get_download_url()

        self.assertEqual(url, 'https://github.com/frida/frida/releases/download/'
                              '10.6.8/frida-gadget-10.6.8-android-x86.so.xz')

    def test_throws_exception_when_download_url_could_not_be_determined(self):
        mock_github = mock.MagicMock()
        mock_github.get_assets.return_value = self.github_get_assets_sample

        self.android_gadget.github = mock_github
        self.android_gadget.architecture = 'arm'

        # the method we actually testing here!
        with self.assertRaises(Exception) as _:
            self.android_gadget._get_download_url()


class TestAndroidPatcher(unittest.TestCase):
    @mock.patch('objection.utils.patchers.android.BasePlatformPatcher.__init__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.android.AndroidPatcher.__del__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.android.tempfile')
    def test_inits_patcher(self, tempfile):
        tempfile.mkdtemp.return_value = '/tmp/test'

        patcher = AndroidPatcher()

        self.assertIsNone(patcher.apk_source)
        self.assertEqual(patcher.apk_temp_directory, '/tmp/test')
        self.assertEqual(patcher.apk_temp_frida_patched, '/tmp/test.objection.apk')
        self.assertFalse(patcher.skip_cleanup)
        self.assertTrue('objection/utils/patchers/../assets/objection.jks' in patcher.keystore)
        self.assertTrue(os.path.exists(patcher.keystore))

    @mock.patch('objection.utils.patchers.android.AndroidPatcher.__init__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.android.AndroidPatcher.__del__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.android.tempfile')
    @mock.patch('objection.utils.patchers.android.os')
    def test_set_android_apk_source(self, _, mock_os):
        mock_os.path.exists.return_value = True
        patcher = AndroidPatcher()

        source = patcher.set_apk_source('foo.apk')

        self.assertEqual(type(source), AndroidPatcher)
        self.assertEqual(patcher.apk_source, 'foo.apk')
