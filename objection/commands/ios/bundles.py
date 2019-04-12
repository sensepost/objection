import click
from tabulate import tabulate

from objection.state.connection import state_connection
from objection.utils.helpers import pretty_concat


def _should_include_apple_bundles(args: list) -> bool:
    """
        Checks if arguments have the --include-apple-frameworks flag

        :param args:
        :return:
    """

    return len(args) > 0 and '--include-apple-frameworks' in args


def _should_print_full_path(args: list) -> bool:
    """
        Checks if arguments have the --full-path flag

        :param args:
        :return:
    """

    return len(args) > 0 and '--full-path' in args


def _is_apple_bundle(bundle: str) -> bool:
    """
        Check if a string bundle identifier is considered an Apple
        bundle based on the fact that the bundle name starts with
        the string com.apple

        :param bundle:
        :return:
    """

    # This is a bit of an assumption, but ok.
    if bundle is None:
        return False

    if bundle.startswith('com.apple'):
        return True

    return False


def show_frameworks(args: list = None) -> None:
    """
        Prints information about bundles that represent frameworks.

        https://developer.apple.com/documentation/foundation/nsbundle/1408056-allframeworks?language=objc

        :param args:
        :return:
    """

    api = state_connection.get_api()
    frameworks = api.ios_bundles_get_frameworks()

    # apply filters
    if not _should_include_apple_bundles(args):
        frameworks = [f for f in frameworks if not _is_apple_bundle(f['bundle'])]

    # Just dump it to the screen
    click.secho(tabulate(
        [[
            entry['executable'],
            entry['bundle'],
            entry['version'],
            entry['path'] if _should_print_full_path(args) else pretty_concat(entry['path'], 40, True),
        ] for entry in frameworks
        ], headers=['Executable', 'Bundle', 'Version', 'Path'],
    ))


def show_bundles(args: list = None) -> None:
    """
        Prints information about bundles that are not nessesarily frameworks

        https://developer.apple.com/documentation/foundation/nsbundle/1413705-allbundles?language=objc

        :param args:
        :return:
    """

    api = state_connection.get_api()
    bundles = api.ios_bundles_get_bundles()

    # Just dump it to the screen
    click.secho(tabulate(
        [[
            entry['executable'],
            entry['bundle'],
            entry['version'],
            entry['path'] if _should_print_full_path(args) else pretty_concat(entry['path'], 40, True),
        ] for entry in bundles
        ], headers=['Executable', 'Bundle', 'Version', 'Path'],
    ))
