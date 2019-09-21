import logging
import os
import traceback

import click
import delegator
import frida
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import FuzzyCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from objection.utils.agent import Agent
from .commands import COMMANDS
from .completer import CommandCompleter
from ..__init__ import __version__
from ..commands.device import get_device_info
from ..state.app import app_state
from ..state.connection import state_connection
from ..utils.helpers import get_tokens


class Repl(object):
    """
        The exploration REPL for objection
    """

    def __init__(self) -> None:
        self.cli = None
        self.prompt_tokens = []

        self.completer = FuzzyCompleter(CommandCompleter())
        self.commands_repository = COMMANDS
        self.session = self.get_prompt_session()

    def get_prompt_session(self) -> PromptSession:
        """
            Starts a new prompt session.

            :return:
        """

        return PromptSession(
            history=FileHistory(os.path.expanduser('~/.objection/objection_history')),
            completer=self.completer,
            style=self.get_prompt_style(),
            auto_suggest=AutoSuggestFromHistory(),
            reserve_space_for_menu=4,
            complete_in_thread=True,
        )

    @staticmethod
    def get_prompt_style() -> Style:
        """
            Get the style to use for our prompt

            :return:
        """

        return Style.from_dict({
            # completions menu
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'completion-menu.completion': 'bg:#008888 #ffffff',

            # fuzzy match outside
            'completion-menu.completion fuzzymatch.outside': 'fg:#000000',

            # Prompt.
            'applicationname': '#007cff',
            'on': '#00aa00',
            'devicetype': '#00ff48',
            'version': '#00ff48',
            'connection': '#717171'
        })

    def set_prompt_tokens(self, device_info: tuple) -> None:
        """
            Set prompt tokens sourced from a command.device.device_info()
            call.

            :param device_info:
            :return:
        """
        device_name, system_name, model, system_version = device_info

        self.prompt_tokens = [
            ('class:applicationname', device_name),
            ('class:on', ' on '),
            ('class:devicetype', '(' + model + ': '),
            ('class:version', system_version + ') '),
            ('class:connection', '[' + state_connection.get_comms_type_string() + '] # '),
        ]

    def get_prompt_message(self) -> list:
        """
            Return prompt tokens to use in the cli app.

            If none were set during the init of this class, it
            is assumed that the connection failed.

            :return:
        """

        if self.prompt_tokens:
            return self.prompt_tokens

        return [
            ('class:applicationname', 'unknown application'),
            ('class:on', ''),
            ('class:devicetype', ''),
            ('class:version', ' '),
            ('class:connection', '[' + state_connection.get_comms_type_string() + '] # '),
        ]

    def run_command(self, document: str) -> None:
        """
            Process a command as received by prompt_toolkit.

            :param document:
            :return:
        """

        logging.info(document)

        if document.strip() == '':
            return

        # handle os commands
        if document.strip().startswith('!'):

            # strip the leading !
            os_cmd = document[1:]

            click.secho('Running OS command: {0}\n'.format(os_cmd), dim=True)

            o = delegator.run(os_cmd, binary=True)

            # print stdout
            if len(o.out) > 0:
                click.secho(o.out.decode('utf-8', 'replace'), bold=True)

            # print stderr
            if len(o.err) > 0:
                click.secho(o.err.decode('utf-8', 'replace'), fg='red')

            return

        # a normal command is to be run, extract the tokens and
        # find which method we should be calling
        tokens = get_tokens(document)

        # check if we should be presenting help instead of executing
        # a command. this is indicated by the fact that the command
        # starts with the word 'help'
        if len(tokens) > 0 and 'help' == tokens[0]:

            # skip the 'help' entry from the tokens list so that
            # the following method can find the correct help
            tokens.remove('help')
            command_help = self._find_command_help(tokens)

            if not command_help:
                click.secho(('No help found for: {0}. Either the command '
                             'does not exist or contains subcommands with help.'
                             ).format(' '.join(tokens)), fg='yellow')
                return

            # output the help and leave
            click.secho(command_help, fg='blue', bold=True)
            return

        # find an execution method to run
        token_matches, exec_method = self._find_command_exec_method(tokens)

        if exec_method is None:
            click.secho('Unknown or ambiguous command: `{0}`. Try `help {0}`.'.format(document), fg='yellow')
            return

        # strip the command matching tokens and leave
        # the rest as arguments
        arguments = tokens[token_matches:]

        # run the method for the command itself!
        exec_method(arguments)

        app_state.add_command_to_history(command=document)

    def _find_command_exec_method(self, tokens: list) -> tuple:
        """
            Attempt to find the actual python method to run
            for the command tokens we have.

            This is done by 'walking' the command dictionary,
            looking for the deepest 'exec' method definition. We are
            interested in the number of tokens walked as well, so
            that the calling command can know how many tokens to
            strip, sending the rest as arguments to the exec method.

            :param tokens:
            :return:
        """

        # start with all of the commands we have
        dict_to_walk = self.commands_repository

        # ... and an empty method to execute
        exec_method = None

        # keep count of the number of tokens
        # used in this walk. this will help indicate to
        # the caller how many tokens should be stripped to
        # get to the arguments for the command
        walked_tokens = 0

        for token in tokens:

            # increment the walked tokens
            walked_tokens += 1

            # check if the token matches a command
            if token in dict_to_walk:

                # matched a dict for the token we have. we need
                # to have *all* of the tokens match a nested dict
                # so that we can extract the final 'exec' key.
                # if we encounter a key that does not have nested commands,
                # chances are we are where we need to be to exec a command.
                if 'commands' not in dict_to_walk[token]:

                    if 'exec' in dict_to_walk[token]:
                        exec_method = dict_to_walk[token]['exec']
                        break

                else:
                    dict_to_walk = dict_to_walk[token]['commands']

            # stop if there is nothing that matches
            else:
                break

        return walked_tokens, exec_method

    def _find_command_help(self, tokens: list) -> str:
        """
            Attempt to find help for a command.

            Just like how the _find_command_exec_method works, this
            method also walks the command dictionary, searching for
            the deepest key. The tokens that match form part of a
            new list, later joined together to pickup the correct
            help.txt.

            :param tokens:
            :return:
        """

        # start with all of the commands we have
        dict_to_walk = self.commands_repository
        helpfile_name = []
        user_help = ''

        for token in tokens:

            # check if the token matches a command
            if token in dict_to_walk:

                # add this token to the helpfile
                helpfile_name.append(token)

                # if there are subcommands, continue with the walk
                if 'commands' in dict_to_walk[token]:
                    dict_to_walk = dict_to_walk[token]['commands']

            # stop if we don't have a token that matches anything
            else:
                break

        # once we have the help, load its .txt contents
        if len(helpfile_name) > 0:

            help_file = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                     'helpfiles', '.'.join(helpfile_name) + '.txt')

            # no helpfile... warn.
            if not os.path.exists(help_file):
                click.secho('Unable to find helpfile {0}'.format(' '.join(helpfile_name)), dim=True)

                return user_help

            # read the helpfile
            with open(help_file, 'r') as f:
                user_help = f.read()

        return user_help

    def handle_reconnect(self, document: str) -> bool:
        """
            Handles a reconnection attempt to a device.

            A reconnection means that the current agent will be unloaded
            and reloaded again.

            :param document:
            :return:
        """

        if document.strip() in ('reconnect', 'reset'):

            click.secho('Reconnecting...', dim=True)

            try:
                state_connection.agent.unload()

                agent = Agent()
                agent.inject()
                state_connection.agent = agent

                self.set_prompt_tokens(get_device_info())
                click.secho('Reconnection successful!', fg='green')

            except (frida.ServerNotRunningError, frida.TimedOutError) as e:
                click.secho('Failed to reconnect with error: {0}'.format(e), fg='red')

            return True

        return False

    def start_repl(self, quiet: bool) -> None:
        """
            Start the objection repl.
        """

        banner = ("""
     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v{0}

     Runtime Mobile Exploration
        by: @leonjza from @sensepost
""").format(__version__)

        if not quiet:
            click.secho(banner, bold=True)
            click.secho('[tab] for command suggestions', fg='white', dim=True)

        # the main application loop is here, reading inputs provided by
        # prompt_toolkit and sending it off the the needed handlers
        while True:

            try:

                document = self.session.prompt(self.get_prompt_message())

                # check if this is an exit command
                if document.strip() in ('quit', 'exit', 'bye'):
                    click.secho('Exiting...', dim=True)
                    break

                # if we got the reconnect command, handle just that
                if self.handle_reconnect(document):
                    continue

                # dispatch to the command handler. if something goes horribly
                # wrong, catch it instead of crashing the REPL
                try:

                    # find something to run
                    self.run_command(document)

                except frida.core.RPCException as e:
                    click.secho('A Frida agent exception has occurred.', fg='red', bold=True)
                    click.secho('{0}'.format(e), fg='red')
                    click.secho('\nPython stack trace: {}'.format(traceback.format_exc()), dim=True)

                except Exception as e:
                    click.secho(('An unexpected internal exception has occurred. If this '
                                 'looks like a code related error, please file a bug report!'), fg='red', bold=True)
                    click.secho('{0}'.format(e), fg='red')
                    click.secho('\nPython stack trace: {}'.format(traceback.format_exc()), dim=True)

            except KeyboardInterrupt:
                pass

            except EOFError:
                click.secho('Exiting...', dim=True)
                break
