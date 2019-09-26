import os

import click
from objection.utils.plugin import Plugin
from objection.commands.filemanager import _path_exists_ios, _upload_ios
from objection.commands.device import _get_ios_environment
from objection.state.connection import state_connection


class FlexLoader(Plugin):
    """ FlexLoader loads Flex """

    def __init__(self, ns):
        """
            Creates a new instance of the plugin

            :param ns:
        """

        implementation = {
            'meta': 'Work with Flex',
            'commands': {
                'load': {
                    'meta': 'Load flex',
                    'exec': self.load_flex
                }
            }
        }

        super().__init__(__file__, ns, implementation)

        self.inject()

        self.flex_dylib = 'libFlex.arm64.dylib'

    def load_flex(self, args: list):
        """
            Loads flex.

            :param args:
            :return:
        """

        agent = state_connection.get_api()
        device_dylib_path = os.path.join(agent.env_ios_paths()['DocumentDirectory'], self.flex_dylib)

        if not _path_exists_ios(device_dylib_path):
            print('Flex not uploaded, uploading...')
            if not self._upload_flex(device_dylib_path):
                return

        click.secho('Asking flex to load...', dim=True)
        self.api.init_flex(self.flex_dylib)
        click.secho('Flex should be up!', fg='green')

    def _upload_flex(self, location: str) -> bool:
        """
            Uploads Flex to the remote filesystem.

            :return:
        """

        local_flex = os.path.join(os.path.abspath(os.path.dirname(__file__)), self.flex_dylib)

        if not os.path.exists(local_flex):
            click.secho('{0} not available next to plugin file. Please build it!'.format(self.flex_dylib), fg='red')
            return False

        _upload_ios(local_flex, location)

        return True

namespace = 'flex'
plugin = FlexLoader