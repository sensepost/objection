import os

import click

from ..utils.frida_transport import FridaRunner


def load(args):
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
