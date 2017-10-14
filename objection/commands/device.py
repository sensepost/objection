import click
from tabulate import tabulate

from ..state.device import device_state
from ..utils.frida_transport import FridaRunner
from ..utils.helpers import pretty_concat
from ..utils.templates import generic_hook, ios_hook, android_hook


def get_device_info() -> tuple:
    """
        Get device information by first checking which runtimes
        are available, and then extracting information about the
        device based on the result.
    """

    hook = generic_hook('device-type')

    runner = FridaRunner()
    runner.run(hook=hook)

    # pop the last response off the runner object
    response = runner.get_last_message()

    if not response.is_successful():
        msg = 'Failed to determine device type!'
        click.secho(msg, fg='red')
        raise Exception(msg)

    # set the frida version from the devicetype response
    device_state.frida_version = response.frida_version

    # ios device information
    if response.device_type == 'ios':
        device_state.device_type = 'ios'

        return _get_ios_device_information()

    # android device information
    if runner.get_last_message().device_type == 'android':
        device_state.device_type = 'android'

        return _get_android_device_information()


def _get_ios_device_information() -> tuple:
    """
        Return information for the currently connected iOS device.

        :return:
    """

    runner = FridaRunner(hook=ios_hook('device-information'))
    runner.run()
    response = runner.get_last_message()

    # we have some device information for iOS, return it!
    if response.is_successful():
        return pretty_concat(response.applicationName, 30, left=True), \
               response.systemName, response.model, response.systemVersion

    raise Exception('Failed to get device information')


def _get_android_device_information() -> tuple:
    """
        Return information for the currently connected Android device.

        :return:
    """

    runner = FridaRunner(hook=android_hook('device-information'))
    runner.run()
    response = runner.get_last_message()

    # we have some device information for iOS, return it!
    if response.is_successful():
        return pretty_concat(response.application_name, 30, left=True), \
               response.device, response.brand, response.version

    raise Exception('Failed to get device information')


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

    hook = ios_hook('filesystem/environment')
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


def _get_android_environment() -> None:
    """
        Prints information about the Android environment.

        :return:
    """

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
