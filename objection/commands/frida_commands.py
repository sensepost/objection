import os

import click
from tabulate import tabulate

from ..utils.frida_transport import FridaRunner
from ..utils.templates import generic_hook


def frida_environment(args: list = None) -> None:
    """
        Prints information about the cirrent Frida environment.

        :param args:
        :return:
    """

    hook = generic_hook('frida')

    runner = FridaRunner(hook=hook)
    runner.run()
    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to get frida environment with error: {}'.format(response.error_reason))
        return

    data = [
        ('Frida Version', response.frida_version),
        ('Process Architecture', response.process_arch),
        ('Process Platform', response.process_platform),
        ('Debugger Attached', response.process_has_debugger)
    ]
    click.secho(tabulate(data), bold=True)


def load_script(args: list) -> None:
    """
        Loads an external Fridascript from the host filesystem
        and executes it as an objection job.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: import <local path to frida-script> (optional name)', bold=True)
        return

    source = args[0]

    # if we have another argument, use that as the name
    if len(args) > 1:
        name = args[1]
    else:
        name = 'user-script'

    # support ~ syntax
    if source.startswith('~'):
        source = os.path.expanduser(source)

    if not os.path.isfile(source):
        click.secho('Unable to import file {0}'.format(source), fg='red')
        return

    with open(source, 'r') as f:
        hook = ''.join(f.read())

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name=name)
