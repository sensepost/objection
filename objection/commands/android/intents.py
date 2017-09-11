import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def launch_activity(args: list) -> None:
    """
        Launches an activity class using an Android Intent

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android intent launch_activity <activity_class>', bold=True)
        return

    intent_class = args[0]

    click.secho('Launching Activity: {0}...'.format(intent_class), dim=True)
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('intent/start-activity'), intent_class=intent_class)
    runner.run()
