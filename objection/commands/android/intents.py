import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags

def _should_dump_backtrace(args: list = None) -> bool:
    """
        Check if --dump-backtrace is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-backtrace' in args

def analyze_implicit_intents(args: list) -> None:
    """
        Analyzes implicit intents in hooked methods.
    """
    api = state_connection.get_api()
    should_backtrace = _should_dump_backtrace(args)

    api.android_intent_analyze(should_backtrace)
    if not should_backtrace:
        click.secho('Started implicit intent analysis', bold=True)
    else:
        click.secho('Started implicit intent analysis with backtrace', bold=True)


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
