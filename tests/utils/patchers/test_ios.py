import unittest
from unittest import mock

from objection.utils.patchers.ios import IosGadget, IosPatcher


class TestIosGadget(unittest.TestCase):
    @mock.patch('objection.utils.patchers.ios.Github')
    @mock.patch('objection.utils.patchers.android.os')
    def setUp(self, mock_github, mock_os):
        mock_os.path.exists.return_value = True

        self.ios_gadget = IosGadget(github=mock_github)

        self.github_get_assets_sample = [
            {
                "url": "https://api.github.com/repos/frida/frida/releases/assets/5005221",
                "id": 5005221,
                "name": "frida-gadget-10.6.8-ios-universal.dylib.xz",
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
                                        "frida-gadget-10.6.8-ios-universal.dylib.xz"
            }
        ]

    def test_gets_gadget_path(self):
        self.ios_gadget.ios_dylib_gadget_path = '/tmp/foo'

        result = self.ios_gadget.get_gadget_path()

        self.assertEqual(result, '/tmp/foo')

    @mock.patch('objection.utils.patchers.ios.os')
    def test_checks_if_gadget_exists(self, mock_os):
        mock_os.path.exists.return_value = True

        result = self.ios_gadget.gadget_exists()

        self.assertTrue(result)

    def test_can_find_asset_download_url(self):
        mock_github = mock.MagicMock()
        mock_github.get_assets.return_value = self.github_get_assets_sample

        self.ios_gadget.github = mock_github

        result = self.ios_gadget._get_download_url()

        self.assertEqual(result, 'https://github.com/frida/frida/releases/download/'
                                 'frida-gadget-10.6.8-ios-universal.dylib.xz')


class TestIosPatcher(unittest.TestCase):
    @mock.patch('objection.utils.patchers.ios.IosPatcher.__init__', mock.Mock(return_value=None))
    @mock.patch('objection.utils.patchers.ios.IosPatcher.__del__', mock.Mock(return_value=None))
    def test_sets_provisioning_profile(self):
        patcher = IosPatcher()
        patcher.set_provsioning_profile('profile.mobileprovision')

        self.assertEqual(patcher.provision_file, 'profile.mobileprovision')
