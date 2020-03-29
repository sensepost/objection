import click
from tabulate import tabulate

from objection.state.connection import state_connection


def entries(args: list = None) -> None:
    """
        Lists entries in the Android KeyStore

        :param args:
        :return:
    """

    api = state_connection.get_api()
    ks = api.android_keystore_list()

    output = [[x['alias'], x['is_key'], x['is_certificate']] for x in ks]
    click.secho(tabulate(output, headers=['Alias', 'Key', 'Certificate']))


def clear(args: list = None) -> None:
    """
        Clears out an Android KeyStore

        :param args:
        :return:
    """

    if not click.confirm('Are you sure you want to clear the Android keystore?'):
        return

    api = state_connection.get_api()
    api.android_keystore_clear()


def watch(args: list = None) -> None:
    """
        Watches usage of the Android KeyStore

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_keystore_watch()
