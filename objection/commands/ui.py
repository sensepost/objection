import click

from ..state.device import device_state
from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook


def alert(args=None):
    if len(args) <= 0:
        message = 'objection!'
    else:
        message = args[0]

    if device_state.device_type == 'ios':
        return _alert_ios(message)

    if device_state.device_type == 'android':
        return None


def _alert_ios(message):
    """
        Display an alert on iOS

        :param message:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('ui/alert'), message=message)
    runner.run()


def ios_screenshot(args=None):
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

    with open(destination, 'w') as f:
        f.write(image)

    click.secho('Screenshot saved to: {0}'.format(destination), fg='green')


def dump_ios_ui(args=None):
    hook = ios_hook('ui/dump')

    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to dump UI with error: {0}'.format(response.error_message), fg='red')
        return

    click.secho(response.data)


def bypass_touchid(args=None):
    hook = ios_hook('ui/touchid')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='touchid-bypass')
