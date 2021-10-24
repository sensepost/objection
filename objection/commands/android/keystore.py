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


def entries(args: list = None) -> None:
    """
        Lists entries in the Android KeyStore

        :param args:
        :return:
    """

    api = state_connection.get_api()
    ks = api.android_keystore_list()

    output = [[x['alias'], x['is_key'], x['is_certificate']] for x in ks]
    click.secho(tabulate(output, headers=['Alias', 'Key', 'Certificate']))


def detail(args: list = None) -> None:
    """
        Lists details of all items in the Android KeyStore

        :param args:
        :return:
    """

    click.secho('Listing details for all items in the Android KeyStore...', dim=True)
    api = state_connection.get_api()
    ks = api.android_keystore_detail()

    if _should_output_json(args):
        click.secho(json.dumps(ks, indent=2, sort_keys=True))
        return

    output = [[
        x['keystoreAlias'],
        x['keyAlgorithm'],
        x['keySize'],
        ','.join(x['blockModes']),
        ','.join(x['encryptionPaddings']),
        ','.join(x['digests']),
        x['keyValidityStart'],
        x['origin'],
        x['purposes'],
        ','.join(x['signaturePaddings']),
        x['isInsideSecureHardware'],
    ] for x in ks]

    click.secho(tabulate(output, headers=[
        'Alias', 'Alg', 'Size', 'Modes', 'Paddings', 'Digests',
        'Validity Start', 'Origin', 'Purposes', 'Sig Paddings', 'Sec Hardware'
    ]))

    # print(ks)


def clear(args: list = None) -> None:
    """
        Clears out an Android KeyStore

        :param args:
        :return:
    """

    if not click.confirm('Are you sure you want to clear the Android keystore?'):
        return

    api = state_connection.get_api()
    api.android_keystore_clear()


def watch(args: list = None) -> None:
    """
        Watches usage of the Android KeyStore

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_keystore_watch()
