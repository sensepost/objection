import json

import click
from tabulate import tabulate

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def _should_dump_json(args: list) -> bool:
    """
        Check if --json is part of the arguments.

        :param args:
        :return:
    """

    return '--json' in args


def get(args: list) -> None:
    """
        Gets cookies using the iOS NSHTTPCookieStorage sharedHTTPCookieStorage
        and prints them to the screen.

        :param args:
        :return:
    """

    hook = ios_hook('binarycookie/get')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get cookies with error: {0}'.format(
            response.error_reason), fg='red')
        return

    if not response.data:
        click.secho('No cookies found')
        return

    if _should_dump_json(args):
        print(json.dumps(response.data, indent=4))
        return

    data = []

    for cookie in response.data:
        data.append([
            cookie['name'],
            cookie['value'],
            cookie['expiresDate'],
            cookie['domain'],
            cookie['path'],
            cookie['isSecure'],
            cookie['isHTTPOnly']
        ])

    click.secho(tabulate(data, headers=['Name', 'Value', 'Expires', 'Domain', 'Path', 'Secure', 'HTTPOnly']), bold=True)
