import click
from tabulate import tabulate

from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook


def get(args=None):
    hook = ios_hook('binarycookie/get')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get cookies with error: {0}'.format(response.error_reason), fg='red')
        return

    if not response.data:
        click.secho('No cookies found')
        return

    data = []

    for cookie in response.data:
        data.append([
            cookie['name'],
            cookie['value'],
            cookie['expiresDate'],
            cookie['domain'],
            cookie['path'],
            cookie['isSecure']
        ])

    click.secho(tabulate(data, headers=['Name', 'Value', 'Expires', 'Domain', 'Path', 'Secure']), bold=True)
