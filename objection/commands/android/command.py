import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def execute(args: list) -> None:
    """
        Runs a shell command on an Android device.

        :param args:
        :return:
    """

    command = ' '.join(args)

    click.secho('Running command: {0}\n'.format(command), dim=True)

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('command/exec'), command=command)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to run command with error: {0}'.format(response.error_reason), fg='red')
        return

    if response.stdout:
        click.secho(response.stdout, bold=True)

    if response.stderr:
        click.secho(response.stderr, bold=True, fg='red')
