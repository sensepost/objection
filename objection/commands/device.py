import click
from tabulate import tabulate

from ..state.connection import state_connection
from ..state.device import device_state, Android, Ios, Macos


def get_environment(args: list = None) -> None:
    """
        Get information about the current environment.

        This method will call the correct runtime specific
        method to get the information that it can.

        :param args:
        :return:
    """

    if device_state.platform == Ios:
        _get_ios_environment()

    if device_state.platform == Android:
        _get_android_environment()

    if device_state.platform == Macos:
        _get_macos_environment()


def _get_ios_environment() -> None:
    """
        Prints information about the iOS environment.

        This includes the current OS version as well as directories
        of interest for the current applications Documents, Library and
        main application bundle.

        :return:
    """

    paths = state_connection.get_api().env_ios_paths()

    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))


def _get_android_environment() -> None:
    """
        Prints information about the Android environment.

        :return:
    """

    paths = state_connection.get_api().env_android_paths()

    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))


def _get_macos_environment() -> None:
    """
        Prints information about the macOS environment.

        This includes the current OS version as well as directories
        of interest for the current applications Documents, Library and
        main application bundle.

        :return:
    """

    paths = state_connection.get_api().env_ios_paths()

    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))
