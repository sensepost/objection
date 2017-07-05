import os

import click

from objection.commands import filemanager
from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def cat(args: list = None) -> None:
    """
        Parses a plist on an iOS device and echoes it in a more human
        readable way.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios plist cat <remote_plist>', bold=True)
        return

    plist = args[0]

    if not os.path.isabs(plist):
        pwd = filemanager.pwd()
        plist = os.path.join(pwd, plist)

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('plist/get'), plist=plist)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get plist with error: {0}'.format(response.error_reason), fg='red')
        return

    click.secho(response.data, bold=True)
