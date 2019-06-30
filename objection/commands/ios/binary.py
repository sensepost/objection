import click
from tabulate import tabulate

from objection.state.connection import state_connection


def info(args: list) -> None:
    """
        Gets cookies using the iOS NSHTTPCookieStorage sharedHTTPCookieStorage
        and prints them to the screen.

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
            information['stackExec'],
            information['rootSafe']
        ] for name, information in binary_info.items()],
        headers=['Name', 'Type', 'Encrypted', 'PIE', 'Stack Exec', 'RootSafe'],
    ))
