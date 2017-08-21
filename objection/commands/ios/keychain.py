import json

import click
from tabulate import tabulate

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def _should_output_json(args: list) -> None:
    """
        Checks if --json is in the list of tokens recieved from the
        command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--json' in args


def dump(args: list = None) -> None:
    """
        Dump the iOS keychain

        :param args:
        :return:
    """

    if _should_output_json(args) and len(args) < 2:
        click.secho('Usage: ios keychain dump (--json <local destination>)', bold=True)
        return

    click.secho('Reading the keychain...', dim=True)
    hook = ios_hook('keychain/dump')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get keychain items with error: {0}'.format(response.error_message), fg='red')
        return

    if _should_output_json(args):
        click.secho('Writing full keychain as json...', dim=True)

        destination = args[1] if len(args[1]) > 0 else 'keychain.json'
        with open(destination, 'w') as f:
            f.write(json.dumps(response.data, indent=2))

        click.secho('Dumped full keychain to: {0}'.format(destination), fg='green')
        return

    # refer to hooks/ios/keychain/dump.js for a key,value reference

    data = []

    if response.data:
        for entry in response.data:
            data.append([entry['item_class'], entry['account'], entry['service'], entry['generic'], entry['access_control'], entry['data'], ])

        click.secho('Get all of the attributes by adding `--json keychain.json` to this command', dim=True)
        click.secho('')
        click.secho(tabulate(data, headers=['Class', 'Account', 'Service', 'Generic', 'Access Control', 'Data']))

    else:
        click.secho('No keychain data could be found', fg='yellow')


def clear(args: list = None) -> None:
    """
        Clear the iOS keychain.

        :param args:
        :return:
    """

    click.secho('Clearing the keychain...', dim=True)
    hook = ios_hook('keychain/clear')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to clear keychain items with error: {0}'.format(response.error_message), fg='red')
        return

    click.secho('Keychain cleared', fg='green')
