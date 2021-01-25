import click
from objection.state.connection import state_connection


def android_proxy_set(args: list = None) -> None:
    """
        Sets a proxy specifically within the application.

        :param args:
        :return:
    """

    if len(args) != 2:
        click.secho('Usage: android proxy set <ip address> <port>', bold=True)
        return

    api = state_connection.get_api()
    api.android_proxy_set(args[0], args[1])
