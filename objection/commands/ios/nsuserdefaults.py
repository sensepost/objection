import click

from objection.state.connection import state_connection


def get(args: list = None) -> None:
    """
        Gets all of the values stored in NSUserDefaults and prints
        them to screen.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    defaults = api.ios_nsuser_defaults_get()

    click.secho(defaults, bold=True)
