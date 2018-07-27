import click
from tabulate import tabulate

from ..state.connection import state_connection
from ..state.device import device_state
from ..utils.frida_transport import FridaRunner
from ..utils.helpers import pretty_concat
from ..utils.templates import android_hook


def get_device_info() -> tuple:
    """
        Get device information by first checking which runtimes
        are available, and then extracting information about the
        device based on the result.
    """

    api = state_connection.get_api()
    environment = api.env_runtime()

    # ios device information
    if environment == 'ios':
        device_state.device_type = 'ios'
        package_info = api.env_ios()

        return pretty_concat(package_info['applicationName'], 30, left=True), \
               package_info['systemName'], package_info['model'], package_info['systemVersion']

    # android device information
    if environment == 'android':
        device_state.device_type = 'android'
        package_info = api.env_android()

        return pretty_concat(package_info['application_name'], 30, left=True), \
               package_info['device'], package_info['brand'], package_info['version']


def get_environment(args: list = None) -> None:
    """
        Get information about the current environment.

        This method will call the correct runtime specific
        method to get the information that it can.

        :param args:
        :return:
    """

    if device_state.device_type == 'ios':
        _get_ios_environment()

    if device_state.device_type == 'android':
        _get_android_environment()


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

    return

    hook = android_hook('filesystem/environment')
    runner = FridaRunner(hook=hook)
    runner.run()
    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get environment directories.', fg='red')
        return

    data = response.data

    directories = []
    for name, directory in data.items():
        directories.append([name, directory])

    click.secho('')
    click.secho(tabulate(directories, headers=['Name', 'Path']))
