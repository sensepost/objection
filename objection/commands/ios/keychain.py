import json

import click
from tabulate import tabulate

from objection.state.connection import state_connection


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
        click.secho('Save the output by adding `--json keychain.json` to this command', dim=True)

    click.secho('Dumping the iOS keychain...', dim=True)
    api = state_connection.get_api()
    keychain = api.ios_keychain_list()

    if _should_output_json(args):
        destination = args[1]

        click.secho('Writing keychain as json to {0}...'.format(destination), dim=True)

        with open(destination, 'w') as f:
            f.write(json.dumps(keychain, indent=2))

        click.secho('Dumped keychain to: {0}'.format(destination), fg='green')
        return

    # Just dump it to the screen
    click.secho(tabulate(
        [[
            entry['create_date'],
            entry['accessible_attribute'].replace('kSecAttrAccessible',
                                                  '') if 'accessible_attribute' in entry else None,
            entry['access_control'],
            entry['item_class'].replace('kSecClassGeneric', ''),
            entry['account'],
            entry['service'],
            entry['data']
        ] for entry in keychain], headers=['Created', 'Accessible', 'ACL', 'Type', 'Account', 'Service', 'Data'],
    ))


def clear(args: list = None) -> None:
    """
        Clear the iOS keychain.

        :param args:
        :return:
    """

    if not click.confirm('Are you sure you want to clear the iOS keychain?'):
        return

    click.secho('Clearing the keychain...', dim=True)

    api = state_connection.get_api()
    api.ios_keychain_empty()

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

    api = state_connection.get_api()
    if api.ios_keychain_add(key, value):
        click.secho('Successfully added the keychain item', fg='green')
        return

    click.secho('Failed to add the keychain item', fg='red')
