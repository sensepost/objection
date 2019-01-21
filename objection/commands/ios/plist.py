import os

import click

from objection.commands import filemanager
from objection.state.connection import state_connection


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

    api = state_connection.get_api()
    plist_data = api.ios_plist_read(plist)

    click.secho(plist_data, bold=True)
