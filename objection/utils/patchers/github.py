import requests


class Github(object):
    """ Interact with Github """

    GITHUB_LATEST_RELEASE = 'https://api.github.com/repos/frida/frida/releases/latest'
    GITHUB_TAGGED_RELEASE = 'https://api.github.com/repos/frida/frida/releases/tags/{tag}'

    # the 'context' of this Github instance
    gadget_version = None

    def __init__(self, gadget_version: str = None):
        """
            Init a new instance of Github
        """

        if gadget_version:
            self.gadget_version = gadget_version

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

    def set_latest_version(self) -> str:
        """
            Call Github and get the tag_name of the latest
            release.

            :return:
        """

        self.gadget_version = self._call(self.GITHUB_LATEST_RELEASE)['tag_name']

        return self.gadget_version

    def get_assets(self) -> dict:
        """
            Gets the assets for the currently selected gadget_version.

            :return:
        """

        assets = self._call(self.GITHUB_TAGGED_RELEASE.format(tag=self.gadget_version))

        if 'assets' not in assets:
            raise Exception(('Unable to determine assets for gadget version \'{0}\'. '
                             'Are you sure this version is available on Github?').format(self.gadget_version))

        return assets['assets']
