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
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style

from .commands import COMMANDS
from .completer import CommandCompleter
from ..__init__ import __version__
from ..state.app import app_state
from ..state.connection import state_connection
from ..utils.agent import Agent, AgentConfig
from ..utils.helpers import get_tokens


class Repl(object):
    """
        The exploration REPL for objection
    """

    def __init__(self) -> None:
        self.cli = None

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
            'status': '#717171',
            'on': '#00aa00',
            'devicetype': '#00ff48',
            'version': '#00ff48',
            'jobs': '',  # TODO
            'connection': '#717171'
        })

    @staticmethod
    def get_prompt_message() -> list:
        """
            Return prompt tokens to use in the cli app.

            If none were set during the init of this class, it
            is assumed that the connection failed.

            :return:
        """

        agent = state_connection.agent
        dev = state_connection.get_agent().device
        params = dev.query_system_parameters()

        return [
            ('class:applicationname', state_connection.name),
            ('class:status', ' (' + ('run' if agent.resumed else 'pause') + ')'),
            ('class:on', ' on '),
            ('class:devicetype', '(' + params['os']['name'] + ': '),
            ('class:version', params['os']['version'] + ') '),
            ('class:connection', '[' + dev.type + '] # '),
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

    @staticmethod
    def perform_reconnect() -> bool:
        """
            Performs the actual reconnection logic.

            :return: True if successful, False otherwise
        """
        try:
            # Get current connection config
            current_agent = state_connection.agent

            # Cleanup current agent (ignore errors if already destroyed)
            click.secho('Unloading current agent...', dim=True)
            try:
                if current_agent.script:
                    current_agent.script.unload()
            except (frida.InvalidOperationError, Exception):
                pass  # Script already destroyed or detached

            try:
                if current_agent.session:
                    current_agent.session.detach()
            except (frida.InvalidOperationError, Exception):
                pass  # Session already detached

            # Create new agent with same config
            click.secho('Creating new agent session...', dim=True)
            new_agent = Agent(AgentConfig(
                name=state_connection.name,
                host=state_connection.host,
                port=state_connection.port,
                device_type=state_connection.device_type,
                device_id=state_connection.device_id,
                spawn=False,  # Don't spawn on reconnect, attach to existing
                foremost=state_connection.foremost,
                debugger=state_connection.debugger,
                pause=not state_connection.no_pause,
                uid=state_connection.uid
            ))

            new_agent.run()
            state_connection.set_agent(new_agent)

            click.secho('Successfully reconnected!', fg='green')
            return True

        except (frida.ServerNotRunningError, frida.TimedOutError) as e:
            click.secho('Failed to reconnect with error: {0}'.format(e), fg='red')
            return False
        except Exception as e:
            click.secho('Failed to reconnect: {0}'.format(e), fg='red')
            return False

    @staticmethod
    def handle_reconnect(document: str) -> bool:
        """
            Handles a reconnection attempt to a device.

            A reconnection means that the current agent will be unloaded
            and reloaded again.

            :param document:
            :return:
        """

        if document.strip() in ('reconnect', 'reset'):
            click.secho('Reconnecting...', dim=True)
            Repl.perform_reconnect()
            return True

        return False

    def run(self, quiet: bool) -> None:
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
        # prompt_toolkit and sending it off the needed handlers
        while True:

            try:
                with patch_stdout(raw=True):
                    document = self.session.prompt(self.get_prompt_message())

                    # check if this is an exit command
                    if document.strip() in ('quit', 'exit', 'bye'):
                        click.secho('Exiting...', dim=True)
                        break

                    if document.strip() in ('resume', 'res'):
                        click.secho('Resuming attached process', dim=True)
                        state_connection.agent.resume()
                        continue

                    # if we got the reconnect command, handle just that
                    if self.handle_reconnect(document):
                        continue

                    # dispatch to the command handler. if something goes horribly
                    # wrong, catch it instead of crashing the REPL
                    try:

                        # find something to run
                        self.run_command(document)

                    except frida.InvalidOperationError as e:
                        # Check if script was destroyed - attempt auto-reconnect
                        if 'script has been destroyed' in str(e).lower() or 'script is destroyed' in str(e).lower():
                            click.secho('Script has been destroyed. Attempting auto-reconnect...', fg='yellow')
                            if self.perform_reconnect():
                                click.secho('Reconnected! Please retry your command.', fg='green')
                            else:
                                click.secho('Auto-reconnect failed. Use "reconnect" to try again manually.', fg='red')
                        else:
                            click.secho('A Frida operation error has occurred.', fg='red', bold=True)
                            click.secho('{0}'.format(e), fg='red')
                            click.secho('\nPython stack trace: {}'.format(traceback.format_exc()), dim=True)

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
