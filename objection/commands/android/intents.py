import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.helpers import clean_argument_flags
from objection.utils.templates import android_hook


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

    click.secho('Launching Activity: {0}...'.format(intent_class), dim=True)
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('intent/start-activity'), intent_class=intent_class)
    runner.run()

    click.secho('Launched: {0}'.format(intent_class), fg='green')


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

    click.secho('Launching Service: {0}...'.format(intent_class), dim=True)

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('intent/start-service'), intent_class=intent_class)
    runner.run()

    click.secho('Launched: {0}'.format(intent_class), fg='green')
