import unittest
from unittest import mock

from objection.utils.patchers.github import Github


class TestGithub(unittest.TestCase):
    def setUp(self):
        self.github = Github()
        self.mock_response = {
            "tag_name": "10.6.9",
            "target_commitish": "master",
            "name": "Frida 10.6.9",
            "created_at": "2017-10-09T23:52:02Z",
            "published_at": "2017-10-10T00:02:48Z",
            "assets": [
                {
                    "url": "https://api.github.com/repos/frida/frida/releases/assets/5024320",
                    "name": "frida-core-devkit-10.6.9-android-arm.tar.xz",
                    "label": "",
                    "updated_at": "2017-10-10T00:13:36Z",
                    "browser_download_url": "https://github.com/frida/frida/releases/download/"
                                            "10.6.9/frida-core-devkit-10.6.9-android-arm.tar.xz"
                },
            ],
            "tarball_url": "https://api.github.com/repos/frida/frida/tarball/10.6.9",
            "zipball_url": "https://api.github.com/repos/frida/frida/zipball/10.6.9",
            "body": "See http://www.frida.re/news/ for details."
        }

    @mock.patch('objection.utils.patchers.github.requests')
    def test_makes_call_and_stores_result_in_cache(self, mock_requests):
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_response

        mock_requests.get.return_value = mock_response

        result = self.github._call('/test')

        self.assertEqual(result, self.mock_response)
        self.assertEqual(len(self.github.request_cache), 1)

    @mock.patch('objection.utils.patchers.github.requests')
    def test_makes_call_and_stores_result_in_cache_and_fetches_next_from_cache(self, mock_requests):
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_response

        mock_requests.get.return_value = mock_response

        self.github._call('/test')

        # entry is now stored in cache, update the next response object
        # and make the request again.
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'other'}

        mock_requests.get.return_value = mock_response

        result = self.github._call('/test')

        self.assertEqual(result, self.mock_response)

    @mock.patch('objection.utils.patchers.github.requests')
    def test_makes_call_and_gets_latest_version(self, mock_requests):
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_response

        mock_requests.get.return_value = mock_response

        result = self.github.get_latest_version()

        self.assertEqual(result, self.mock_response['tag_name'])

    @mock.patch('objection.utils.patchers.github.requests')
    def test_makes_call_and_fails_to_get_assets(self, mock_requests):
        mock_response = mock.Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {}

        mock_requests.get.return_value = mock_response

        with self.assertRaises(Exception) as _:
            self.github.get_assets()

    @mock.patch('objection.utils.patchers.github.requests')
    def test_makes_call_and_gets_assets(self, mock_requests):
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = self.mock_response

        mock_requests.get.return_value = mock_response

        result = self.github.get_assets()

        self.assertEqual(result, self.mock_response['assets'])
