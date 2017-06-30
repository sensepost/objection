import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def get(args: list = None) -> None:
    """
        Gets all of the values stored in NSUserDefaults and prints
        them to screen.

        :param args:
        :return:
    """

    hook = ios_hook('nsuserdefaults/get')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get nsuserdefaults with error: {0}'.format(response.error_reason), fg='red')
        return

    click.secho(response.data, bold=True)
