import click

from objection.state.connection import state_connection


def live_instances(args: list) -> None:
    """
        Asks the agent to print the currently live instances of a particular class

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap print_instances <class> (eg: com.example.test)', bold=True)
        return

    target_class = args[0]

    api = state_connection.get_api()
    api.android_live_print_class_instances(target_class)
