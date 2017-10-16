import os

import click

from ..state.app import app_state


def history(args: list) -> None:
    """
        Lists the commands that have been run in the current session.

        :param args:
        :return:
    """

    click.secho('Unique commands run in current session:', dim=True)

    for command in app_state.successful_commands:
        click.secho(command)


def save(args: list) -> None:
    """
        Save the current sessions command history to a file.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: commands save <local destination>', bold=True)
        return

    destination = os.path.expanduser(args[0]) if args[0].startswith('~') else args[0]

    with open(destination, 'w') as f:
        for command in app_state.successful_commands:
            f.write('{0}\n'.format(command))

    click.secho('Saved commands to: {0}'.format(destination), fg='green')


def clear(args: list) -> None:
    """
        Clears the current sessions command history.

        :param args:
        :return:
    """

    app_state.clear_command_history()
    click.secho('Commnad history cleared.', fg='green')
