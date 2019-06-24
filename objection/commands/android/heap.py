import click
from tabulate import tabulate

from objection.state.connection import state_connection


def instances(args: list) -> None:
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
    instance_results = api.android_live_get_class_instances(target_class)

    if len(instance_results) <= 0:
        return

    click.secho(tabulate(
        [[
            entry['handleString'],
            entry['className'],
            entry['asString'],
        ] for entry in instance_results], headers=['Handle', 'Class', 'toString()'],
    ))
