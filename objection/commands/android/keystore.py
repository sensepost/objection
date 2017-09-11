import click
from tabulate import tabulate

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def entries(args: list = None) -> None:
    """
        Lists entries in the Android KeyStore

        :param args:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('keystore/list'))
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list KeyStore items with error: {0}'.format(response.error_reason), fg='red')
        return None

    if not response.data:
        click.secho('No keystore items were found', fg='yellow')
        return None

    output = [[x['alias'], x['is_key'], x['is_certificate']] for x in response.data]

    click.secho(tabulate(output, headers=['Alias', 'Is Key', 'Is Certificate']))


def clear(args: list = None) -> None:
    """
        Clears out an Android KeyStore

        :param args:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('keystore/clear'))
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to clear the KeyStore error: {0}'.format(response.error_reason), fg='red')
        return None

    click.secho('Cleared the KeyStore', fg='green')
