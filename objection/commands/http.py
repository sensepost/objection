import click

from ..commands.filemanager import pwd
from ..state.connection import state_connection


def start(args: list) -> None:
    """
        Start's an http server, exposing the mobile devices filesystem.

        :param args:
        :return:
    """

    port = 9000

    if len(args) > 0:
        port = int(args[0])

    click.secho('Starting server on port {port}...'.format(port=port), dim=True)

    api = state_connection.get_api()
    api.http_server_start(pwd(), port)


def stop(args: list) -> None:
    """
        Stops the on device HTTP server

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.http_server_stop()


def status(args: list) -> None:
    """
        Get the status of the HTTP server

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.http_server_status()
