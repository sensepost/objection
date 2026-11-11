import datetime
import os

import click

from ..state.app import app_state


def format_history_timestamp(timestamp: str) -> str:
    """Format a prompt-toolkit timestamp for compact history output."""

    try:
        return datetime.datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M')
    except (TypeError, ValueError):
        return timestamp


def numbered_history(commands: list, timestamps: list = None) -> None:
    """Print a numbered history suitable for selecting or replaying entries."""

    click.secho('Historic commands:', dim=True)

    for number, command in enumerate(commands, start=1):
        timestamp = ''
        if timestamps and number <= len(timestamps) and timestamps[number - 1]:
            timestamp = '{0} '.format(format_history_timestamp(timestamps[number - 1]))

        click.secho('{0} {1}{2}'.format(number, timestamp, command))


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
    click.secho('Command history cleared.', fg='green')
