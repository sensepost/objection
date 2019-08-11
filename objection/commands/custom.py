import os

import click
import frida
from prompt_toolkit import prompt
from prompt_toolkit.lexers import PygmentsLexer
from pygments.lexers.javascript import JavascriptLexer

from ..state.connection import state_connection


def evaluate(args: list) -> None:
    """
        Evaluate JavaScript within the agent's context.

        :param args:
        :return:
    """

    target_file = None

    # if we have an argument, let's assume it is a file path
    if len(args) > 0:

        target_file = args[0]
        p = os.path.expanduser(target_file)
        if os.path.exists(p):
            target_file = p
        else:
            click.secho('Could not find file {p}.'.format(p=target_file), fg='red')
            return

    if target_file:
        with open(target_file, 'r', encoding='utf-8') as f:
            javascript = ''.join(f.readlines())
    else:
        javascript = prompt(
            multiline=True, lexer=PygmentsLexer(JavascriptLexer),
            bottom_toolbar='JavaScript edit mode. [ESC] and then [ENTER] to accept. [CTRL] + C to cancel.').strip()

    if len(javascript) <= 0:
        click.secho('JavaScript to evaluate appears empty. Skipping.', fg='yellow')
        return

    click.secho('JavaScript capture complete. Evaluating...', dim=True)
    try:
        state_connection.get_api().evaluate(javascript)
    except frida.core.RPCException as e:
        click.secho('Failed to load script: {}'.format(e), fg='red', bold=True)
