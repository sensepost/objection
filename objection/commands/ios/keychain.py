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


def _should_do_smart_decode(args: list) -> bool:
    """
        Checks if --smart is in the list of tokens received from the
        command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--smart' in args


def _data_flag_has_identifier(args: list) -> bool:
    """
        Checks that if the data flag is specified, an identifier
        is also passed.

        :param args:
        :return:
    """

    if '--data' in args:
        return any(x in args for x in ['--service', '--account'])

    return True


def _get_flag_value(args: list, flag: str) -> str:
    """
        Returns the value for a flag.

        :param args:
        :param flag:
        :return:
    """

    return args[args.index(flag) + 1] if flag in args else None


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
    keychain = api.ios_keychain_list(_should_do_smart_decode(args))

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


def dump_raw(args: list = None) -> None:
    """
        Dump the iOS keychain, but without any parsing.
        The agent will output the entries it finds here.

        :param args:
        :return:
    """

    click.secho('Note: You may be asked to authenticate using the devices passcode or TouchID')
    click.secho('Dumping the iOS keychain...', dim=True)
    api = state_connection.get_api()
    api.ios_keychain_list_raw()


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
        Adds a new kSecClassGenericPassword keychain entry to the keychain

        :param args:
        :return:
    """

    if not _data_flag_has_identifier(args):
        click.secho('When specifying the --data flag, either --account or '
                    '--server should also be added', fg='red')
        return

    account = _get_flag_value(args, '--account')
    service = _get_flag_value(args, '--service')
    data = _get_flag_value(args, '--data')

    click.secho('Adding a new entry to the iOS keychain...', dim=True)
    click.secho('Account:  {0}'.format(account), dim=True)
    click.secho('Service:  {0}'.format(service), dim=True)
    click.secho('Data:     {0}'.format(data), dim=True)

    api = state_connection.get_api()
    if api.ios_keychain_add(account, service, data):
        click.secho('Successfully added the keychain item', fg='green')
        return

    click.secho('Failed to add the keychain item', fg='red')
