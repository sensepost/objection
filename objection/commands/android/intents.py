import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags


def launch_activity(args: list) -> None:
    """
        Launches an activity class using an Android Intent

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android intent launch_activity <activity_class>', bold=True)
        return

    intent_class = args[0]

    api = state_connection.get_api()
    api.android_intent_start_activity(intent_class)


def launch_service(args: list) -> None:
    """
        Launches an exported service using an Android Intent

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android intent launch_service <service_class>', bold=True)
        return

    intent_class = args[0]

    api = state_connection.get_api()
    api.android_intent_start_service(intent_class)
