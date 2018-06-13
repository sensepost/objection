import json

import click
from tabulate import tabulate

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def _should_output_json(args: list) -> bool:
    """
        Checks if --json is in the list of tokens received from the
        command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--json' in args


def _has_minimum_flags_to_add_item(args: list) -> bool:
    """
        Ensure that all of the flags are present for a keychain
        entry item. At the same time, ensure that each flag has a value.

        :param args:
        :return:
    """

    return all(i in args for i in ['--key', '--data']) and len([
        x for x in args if '--' not in x]) == len([x for x in args if '--' in x])


def _get_flag_value(args: list, flag: str) -> str:
    """
        Returns the value for a flag.

        :param args:
        :param flag:
        :return:
    """

    return args[args.index(flag) + 1]


def dump(args: list = None) -> None:
    """
        Dump the iOS keychain

        :param args:
        :return:
    """

    if _should_output_json(args) and len(args) < 2:
        click.secho('Usage: ios keychain dump (--json <local destination>)', bold=True)
        return

    click.secho('Note: You may be asked to authenticate using the devices passcode or TouchID')

    if not _should_output_json(args):
        click.secho('Get all of the attributes by adding `--json keychain.json` to this command', dim=True)

    click.secho('Reading the iOS keychain...', dim=True)
    hook = ios_hook('keychain/dump')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get keychain items with error: {0}'.format(response.error_message), fg='red')
        return

    if _should_output_json(args):
        destination = args[1]

        click.secho('Writing full keychain as json to {0}...'.format(destination), dim=True)

        with open(destination, 'w') as f:
            f.write(json.dumps(response.data, indent=2))

        click.secho('Dumped full keychain to: {0}'.format(destination), fg='green')
        return

    # refer to hooks/ios/keychain/dump.js for a key,value reference

    data = []

    if response.data:
        for entry in response.data:
            data.append([entry['item_class'], entry['account'], entry['service'], entry['generic'], entry['data'], ])

        click.secho('')
        click.secho(tabulate(data, headers=['Class', 'Account', 'Service', 'Generic', 'Data']))

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


def add(args: list) -> None:
    """
        Adds a new keychain entry to the keychain

        :param args:
        :return:
    """

    if not _has_minimum_flags_to_add_item(args):
        click.secho('Usage: ios keychain add --key <key name> --data <entry data>', bold=True)
        return

    key = _get_flag_value(args, '--key')
    value = _get_flag_value(args, '--data')

    click.secho('Adding a new entry to the iOS keychain...', dim=True)
    click.secho('Key:       {0}'.format(key), dim=True)
    click.secho('Value:     {0}'.format(value), dim=True)

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('keychain/add'))

    api = runner.rpc_exports()

    if api.add(key, value):
        click.secho('Successfully added the keychain item', fg='green')
        return

    click.secho('Failed to add the keychain item', fg='red')
