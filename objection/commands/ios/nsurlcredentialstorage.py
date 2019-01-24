import click
from tabulate import tabulate

from objection.state.connection import state_connection


def dump(args: list = None) -> None:
    """
        Dumps credentials stored in NSURLCredentialStorage

        :param args:
        :return:
    """

    api = state_connection.get_api()
    cookies = api.ios_credential_storage()

    click.secho(tabulate(
        [[
            entry['protocol'],
            entry['host'],
            entry['port'],
            entry['authMethod'].replace('NSURLAuthenticationMethod', ''),
            entry['user'],
            entry['password'],
        ] for entry in cookies], headers=[
            'Protocol', 'Host', 'Port', 'Authentication Method', 'User', 'Password'
        ],
    ))
