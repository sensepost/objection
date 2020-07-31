import os

import click
from tabulate import tabulate

from objection.state.connection import state_connection
from ..utils.helpers import sizeof_fmt, clean_argument_flags


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
        ('Script Runtime', frida_env['runtime']),
        ('Script Filename', frida_env['filename']),
        ('Frida Heap Size', sizeof_fmt(frida_env['heap']))
    ]))


def ping(args: list = None) -> None:
    """
        Pings the agent.

        :param args:
        :return:
    """

    agent = state_connection.get_api()
    if agent.ping():
        click.secho('The agent responds ok!', fg='green')
    else:
        click.secho('The agent did not respond ok!', fg='red')


def load_background(args: list = None) -> None:
    """
        Loads a Frida script and runs it in the background.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: import <local path to frida-script> (optional name)',
                    bold=True)
        return

    source = args[0]

    # support ~ syntax
    if source.startswith('~'):
        source = os.path.expanduser(source)

    if not os.path.isfile(source):
        click.secho('Unable to import file {0}'.format(source), fg='red')
        return

    # read the hook sources
    with open(source, 'r') as f:
        hook = ''.join(f.read())

    agent = state_connection.get_agent()
    agent.background(hook)
