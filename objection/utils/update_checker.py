import random

import click
import requests
from pkg_resources import parse_version

from ..__init__ import __version__


def check_version() -> None:
    """
        Checks if the current version of objection is up to date.

        :return:
    """

    # roll a two sided dice! should maybe use a .objection/version
    # file or something in the future
    if not random.choice([True, False]):
        return

    try:

        r = requests.get('https://api.github.com/repos/sensepost/objection/releases/latest').json()

        if parse_version(r['tag_name']) > parse_version(__version__):
            click.secho('\n\nA newer version of objection is available!', fg='green')
            click.secho('You have v{0} and v{1} is ready for download.\n'.format(
                __version__, r['tag_name']), fg='green')
            click.secho('Upgrade with: pip3 install objection --upgrade', fg='green', bold=True)
            click.secho('For more information, please see: https://github.com/sensepost/objection/wiki/Updating\n',
                        dim=True)

    # Just be quiet about any exceptions here. If this method fails
    # it really doesn't matter.
    except Exception:

        pass
