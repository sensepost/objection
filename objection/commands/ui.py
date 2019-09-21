import click

from objection.state.connection import state_connection
from ..state.device import device_state, Ios, Android


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

    if device_state.device_type == Ios:
        _alert_ios(message)

    if device_state.device_type == Android:
        pass


def _alert_ios(message: str):
    """
        Display an alert on iOS

        :param message:
        :return:
    """

    api = state_connection.get_api()
    api.ios_ui_alert(message)


def ios_screenshot(args: list = None) -> None:
    """
        Take an iOS screenshot.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios ui screenshot <local png destination>', bold=True)
        return

    destination = args[0]

    if not destination.endswith('.png'):
        destination = destination + '.png'

    api = state_connection.get_api()
    png = api.ios_ui_screenshot()

    with open(destination, 'wb') as f:
        f.write(png)

    click.secho('Screenshot saved to: {0}'.format(destination), fg='green')


def dump_ios_ui(args: list = None) -> None:
    """
        Dumps the current iOS user interface in a serialized form.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    ui = api.ios_ui_window_dump()

    click.secho(ui)


def bypass_touchid(args: list = None) -> None:
    """
        Starts a new objection job that hooks into the iOS TouchID
        classes, replacing the verification logic to always pass.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.ios_ui_biometrics_bypass()


def android_screenshot(args: list = None) -> None:
    """
        Take an Android screenshot.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: android ui screenshot <local png destination>', bold=True)
        return

    # add the .png extension if it does not already exist
    destination = args[0] if args[0].endswith('.png') else args[0] + '.png'

    # download the file
    api = state_connection.get_api()
    data = api.android_ui_screenshot()

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

    api = state_connection.get_api()
    api.android_ui_set_flag_secure(args[0])
