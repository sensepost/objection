import click
from tabulate import tabulate

from objection.state.connection import state_connection


def info(args: list) -> None:
    """
        Gets information about binaries and frameworks.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    binary_info = api.ios_binary_info()

    click.secho(tabulate(
        [[
            name,
            information['type'],
            information['encrypted'],
            information['pie'],
            information['arc'],
            information['canary'],
            information['stackExec'],
            information['rootSafe']
        ] for name, information in binary_info.items()],
        headers=['Name', 'Type', 'Encrypted', 'PIE', 'ARC', 'Canary', 'Stack Exec', 'RootSafe'],
    ))
