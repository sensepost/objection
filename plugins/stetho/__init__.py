import os

import click
from objection.utils.plugin import Plugin
from objection.commands.filemanager import _path_exists_android, _upload_android
from objection.commands.device import _get_android_environment
from objection.state.connection import state_connection


class StethoLoader(Plugin):
    """ StethoLoader loads Facebook's stetho """

    def __init__(self, ns):
        """
            Creates a new instance of the plugin

            :param ns:
        """

        implementation = {
            'meta': 'Work with Facebook\'s stetho',
            'commands': {
                'load': {
                    'meta': 'Load stetho',
                    'exec': self.load_stetho
                }
            }
        }

        super().__init__(__file__, ns, implementation)

        self.inject()

        self.stetho_jar = 'stetho.apk'

    def load_stetho(self, args: list):
        """
            Loads stetho.

            :param args:
            :return:
        """

        agent = state_connection.get_api()
        device_jar_path = os.path.join(agent.env_android_paths()['cacheDirectory'], self.stetho_jar)

        if not _path_exists_android(device_jar_path):
            print('Stetho not uploaded, uploading...')
            if not self._upload_stetho(device_jar_path):
                return

        click.secho('Asking stetho to load...', dim=True)
        self.api.init_stetho()

    def _upload_stetho(self, location: str) -> bool:
        """
            Uploads Stetho to the remote filesystem.

            :return:
        """

        local_stetho = os.path.join(os.path.abspath(os.path.dirname(__file__)), self.stetho_jar)

        if not os.path.exists(local_stetho):
            click.secho('{0} not available next to plugin file. Please download Stetho and convert first!'.format(self.stetho_jar), fg='red')
            click.secho('   curl -sL https://github.com/facebook/stetho/releases/download/v1.5.1/stetho-1.5.1-fatjar.jar -O', dim=True)
            click.secho('   dx --dex --output="stetho.apk" stetho-1.5.1.jar', dim=True)
            return False

        _upload_android(local_stetho, location)

        return True

namespace = 'stetho'
plugin = StethoLoader
