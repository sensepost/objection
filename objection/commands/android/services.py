import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def launch_service(args: list) -> None:
    """
        Launches an exported service using an Android Intent
        
        :param args:
        :return:
        """
    
    if len(args) < 1:
        click.secho('Usage: android intent launch_service <service_class>', bold=True)
        return

    intent_class = args[0]

    click.secho('Launching Service: {0}...'.format(intent_class), dim=True)
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('intent/start-service'), intent_class=intent_class)
    runner.run()
