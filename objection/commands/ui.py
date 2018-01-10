import click

from ..state.device import device_state
from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook, android_hook


def alert(args: list = None) -> None:
    """
        Displays an alert message via a popup or a Toast message
        on the mobile device.

        :param args:
        :return:
    """

    if len(args) <= 0:
        message = 'objection!'
    else:
        message = args[0]

    if device_state.device_type == 'ios':
        _alert_ios(message)

    if device_state.device_type == 'android':
        pass


def _alert_ios(message: str):
    """
        Display an alert on iOS

        :param message:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('ui/alert'), message=message)
    runner.run()


def ios_screenshot(args: list = None) -> None:
    """
        Take an iOS screenshot.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios ui screenshot <local png destination>', bold=True)
        return

    destination = args[0] + '.png'

    hook = ios_hook('screenshot/take')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to screenshot with error: {0}'.format(response.error_message), fg='red')
        return

    image = response.get_extra_data()

    with open(destination, 'wb') as f:
        f.write(image)

    click.secho('Screenshot saved to: {0}'.format(destination), fg='green')


def dump_ios_ui(args: list = None) -> None:
    """
        Dumps the current iOS user interface in a serialized form.

        :param args:
        :return:
    """

    hook = ios_hook('ui/dump')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to dump UI with error: {0}'.format(response.error_message), fg='red')
        return

    click.secho(response.data)


def bypass_touchid(args: list = None) -> None:
    """
        Starts a new objection job that hooks into the iOS TouchID
        classes, replacing the verification logic to always pass.

        :param args:
        :return:
    """

    hook = ios_hook('ui/touchid')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='touchid-bypass')


def android_screenshot(args: list = None) -> None:
    """
        Take an Android screenshot.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: android ui screenshot <local png destination>', bold=True)
        return

    # add the .png extention if it does not already exist
    destination = args[0] if args[0].endswith('.png') else args[0] + '.png'

    hook = android_hook('screenshot/take')
    runner = FridaRunner(hook=hook)
    api = runner.rpc_exports()

    # download the file
    data = api.screenshot()

    # cleanup the runner
    runner.unload_script()

    if not data:
        click.secho('Failed to take screenshot.')
        return

    image = bytearray(map(lambda x: x % 256, data))

    with open(destination, 'wb') as f:
        f.write(image)

    click.secho('Screenshot saved to: {0}'.format(destination), fg='green')


def android_flag_secure(args: list = None) -> None:
    """
        Control FLAG_SECURE of the current Activity, allowing or disallowing
        the use of hardware key combinations and screencap to take screenshots.

        :param args:
        :return:
    """

    if len(args) <= 0 or args[0] not in ('true', 'false'):
        click.secho('Usage: android ui FLAG_SECURE <true/false>', bold=True)
        return

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('ui/flag-secure'), value=args[0])

    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to set FLAG_SECURE: {0}'.format(response.error_message), fg='red')
        return

    click.secho('Successfuly set FLAG_SECURE' if response.data else 'Successfully removed FLAG_SECURE')
