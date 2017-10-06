import requests


class Github(object):
    """ Interact with Github """

    GITHUB_RELEASE = 'https://api.github.com/repos/frida/frida/releases/latest'

    def __init__(self):
        """
            Init a new instance of Github
        """

        self.request_cache = {}

    def _call(self, endpoint: str) -> dict:
        """
            Make a call to Github and cache the response.

            :param endpoint:
            :return:
        """

        # return a cached response if possible
        if endpoint in self.request_cache:
            return self.request_cache[endpoint]

        # get a new response
        results = requests.get(endpoint).json()

        # cache it
        self.request_cache[endpoint] = results

        # and return it
        return results

    def get_latest_version(self) -> str:
        """
            Call Github and get the tag_name of the latest
            release.

            :return:
        """

        return self._call(self.GITHUB_RELEASE)['tag_name']

    def get_assets(self) -> dict:
        """
            Gets the assets for the latest release.

            :return:
        """

        return self._call(self.GITHUB_RELEASE)['assets']
