import click
from tabulate import tabulate

from objection.state.connection import state_connection
from ..utils.helpers import sizeof_fmt


def _should_disable_exception_handler(args: list = None) -> bool:
    """
        Checks the arguments if '--no-exception-handler'
        is part of it.

        :param args:
        :return:
    """

    return len(args) > 0 and '--no-exception-handler' in args


def frida_environment(args: list = None) -> None:
    """
        Prints information about the current Frida environment.

        :param args:
        :return:
    """

    frida_env = state_connection.get_api().env_frida()

    click.secho(tabulate([
        ('Frida Version', frida_env['version']),
        ('Process Architecture', frida_env['arch']),
        ('Process Platform', frida_env['platform']),
        ('Debugger Attached', frida_env['debugger']),
        ('Frida Heap Size', sizeof_fmt(frida_env['heap']))
    ]))
