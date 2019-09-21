import click
from tabulate import tabulate

from ..state.connection import state_connection
from ..state.device import device_state, Android, Ios
from ..utils.helpers import pretty_concat


def get_device_info() -> tuple:
    """
        Get device information by first checking which runtimes
        are available, and then extracting information about the
        device based on the result.
    """

    api = state_connection.get_api()

    # set the frida version
    frida = api.env_frida()
    device_state.frida_version = frida['version']

    environment = api.env_runtime()

    # ios device information
    if environment == 'ios':
        device_state.device_type = Ios
        package_info = api.env_ios()

        # {'applicationName': 'za.sensepost.ipewpew',
        # 'deviceName': 'iPhone 7 Plus',
        # 'identifierForVendor': 'foo',
        # 'model': 'iPhone', 'systemName': 'iOS', 'systemVersion': '12.1'}
        device_state.os_version = package_info['systemVersion']

        return pretty_concat(package_info['applicationName'], 30, left=True), \
               package_info['systemName'], package_info['model'], package_info['systemVersion']

    # android device information
    if environment == 'android':
        device_state.device_type = Android
        package_info = api.env_android()

        # {'application_name': 'com.sensepost.apewpew',
        # 'board': 'universal5422', 'brand': 'samsung', 'device': 'foo',
        # 'host': 'foo.bar', 'id': '1234', 'model': 'foo-bar',
        # 'product': 'foo', 'user': 'root', 'version': '7.1.2'}
        device_state.os_version = package_info['version']

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

    if device_state.device_type == Ios:
        _get_ios_environment()

    if device_state.device_type == Android:
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
