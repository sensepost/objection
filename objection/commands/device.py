import click
from tabulate import tabulate

from ..state.device import device_state
from ..utils.frida_transport import FridaRunner
from ..utils.templates import generic_hook, ios_hook


def get_device_info():
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

        hook = ios_hook('device-information')
        runner.run(hook=hook)
        response = runner.get_last_message()

        if response.is_successful():
            return response.deviceName, response.systemName, response.model, response.systemVersion

        raise Exception('Failed to get device information')

    # android device information
    if runner.get_last_message().device_type == 'android':
        device_state.device_type = 'android'
        raise Exception("Not implemented yet")


def get_environment(args=None):
    if device_state.device_type == 'ios':
        _get_ios_environment()

    if device_state.device_type == 'android':
        pass


def _get_ios_environment():
    click.secho(tabulate([get_device_info()], headers=['Name', 'System', 'Model', 'Version']))

    hook = ios_hook('filesystem/environment')
    runner = FridaRunner(hook=hook)
    runner.run()
    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get environment directories.', fg='red')

    data = response.data

    directories = []
    for name, directory in data.items():
        directories.append([name, directory])

    click.secho('')
    click.secho(tabulate(directories, headers=['Name', 'Path']))
