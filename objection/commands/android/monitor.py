import click

from objection.state.connection import state_connection


def string_canary(args: list) -> None:
    """
        Monitors for a string canary argument and reports when
        it is found.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android monitor canary <value> (optional: <filter>)', bold=True)
        return

    target_class = args[0]

    api = state_connection.get_api()
    api.android_live_print_class_instances(target_class)
