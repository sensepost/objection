import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def show_android_classes(args: list = None) -> None:
    """
        Show the currently loaded classes.

        :param args:
        :return:
    """

    hook = android_hook('hooking/list-classes')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list classes with error: {0}'.format(response.error_reason), fg='red')
        return None

    # print the enumerated classes
    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)
