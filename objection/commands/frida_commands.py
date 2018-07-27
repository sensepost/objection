import os

import click
from tabulate import tabulate

from objection.state.connection import state_connection
from ..utils.frida_transport import FridaRunner
from ..utils.helpers import clean_argument_flags, sizeof_fmt
from ..utils.templates import template_env


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


def load_script(args: list) -> None:
    """
        Loads an external Fridascript from the host filesystem
        and executes it as an objection job.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: import <local path to frida-script> (optional name) (optional: --no-exception-handler)',
                    bold=True)
        return

    source = args[0]

    # if we have another argument, use that as the name, if its not an arg
    if len(args) > 1:
        if '--' not in args[1]:
            name = args[1]
        else:
            name = 'user-script-no-exception-handler'
    else:
        name = 'user-script'

    # support ~ syntax
    if source.startswith('~'):
        source = os.path.expanduser(source)

    if not os.path.isfile(source):
        click.secho('Unable to import file {0}'.format(source), fg='red')
        return

    # read the hook sources
    with open(source, 'r') as f:
        hook = ''.join(f.read())

    # wrap the user script in an exception handler, unless we
    # explicitly shouldn't. we also use the generic exception
    # handler as there is no way to know which environment
    # it may be for here.
    if not _should_disable_exception_handler(args):
        err_handler = template_env.get_template('base/generic-base.js')
        hook = err_handler.render(content=hook)

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name=name, args=args)
