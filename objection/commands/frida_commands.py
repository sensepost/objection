import click
from tabulate import tabulate

from ..utils.frida_transport import FridaRunner
from ..utils.templates import generic_hook


def frida_environment(args=None):
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
